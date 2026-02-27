/**
 * C++ Live Text-to-Speech Starter - Backend Server
 *
 * Simple WebSocket proxy to Deepgram's Live TTS API using Crow (HTTP/WS server)
 * and Boost.Beast (outbound WS client). Forwards all messages (JSON and binary)
 * bidirectionally between client and Deepgram.
 *
 * Routes:
 *   GET  /api/session                - Issue JWT session token
 *   GET  /api/metadata               - Project metadata from deepgram.toml
 *   GET  /health                     - Health check
 *   WS   /api/live-text-to-speech    - WebSocket proxy to Deepgram TTS (auth required)
 */

#include <crow.h>
#include <crow/middlewares/cors.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>

#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/kazuho-picojson/defaults.h>
#include <toml.hpp>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>

namespace beast     = boost::beast;
namespace websocket = beast::websocket;
namespace net       = boost::asio;
namespace ssl       = net::ssl;
using tcp           = net::ip::tcp;

// ============================================================================
// CONFIGURATION
// ============================================================================

struct Config {
    std::string deepgram_api_key;
    std::string deepgram_tts_url;
    uint16_t    port;
    std::string host;
    std::string session_secret;
};

/**
 * Generate a cryptographically random hex string of the given byte length.
 */
static std::string random_hex(size_t bytes) {
    static const char hex_chars[] = "0123456789abcdef";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    std::string out;
    out.reserve(bytes * 2);
    for (size_t i = 0; i < bytes * 2; ++i) {
        out.push_back(hex_chars[dis(gen)]);
    }
    return out;
}

/**
 * Read a trimmed environment variable, returning fallback if unset or empty.
 */
static std::string env_or(const char* name, const std::string& fallback) {
    const char* v = std::getenv(name);
    if (!v || std::string(v).empty()) return fallback;
    return std::string(v);
}

/**
 * Load configuration from environment variables with sensible defaults.
 * Reads .env file first (simple KEY=VALUE parser).
 */
static Config load_config() {
    // Minimal .env loader
    std::ifstream env_file(".env");
    if (env_file.is_open()) {
        std::string line;
        while (std::getline(env_file, line)) {
            if (line.empty() || line[0] == '#') continue;
            auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string key = line.substr(0, eq);
            std::string val = line.substr(eq + 1);
            // Remove surrounding quotes if present
            if (val.size() >= 2 &&
                ((val.front() == '"' && val.back() == '"') ||
                 (val.front() == '\'' && val.back() == '\''))) {
                val = val.substr(1, val.size() - 2);
            }
            ::setenv(key.c_str(), val.c_str(), 0); // don't overwrite existing
        }
    }

    Config cfg;
    cfg.deepgram_api_key = env_or("DEEPGRAM_API_KEY", "");
    if (cfg.deepgram_api_key.empty()) {
        std::cerr << "ERROR: DEEPGRAM_API_KEY environment variable is required\n"
                  << "Please copy sample.env to .env and add your API key\n";
        std::exit(1);
    }

    cfg.deepgram_tts_url = "wss://api.deepgram.com/v1/speak";
    cfg.port             = static_cast<uint16_t>(std::stoi(env_or("PORT", "8081")));
    cfg.host             = env_or("HOST", "0.0.0.0");
    cfg.session_secret   = env_or("SESSION_SECRET", random_hex(32));

    return cfg;
}

// ============================================================================
// SESSION AUTH - JWT tokens for production security
// ============================================================================

static constexpr int JWT_EXPIRY_SECONDS = 3600; // 1 hour

/**
 * Generate a signed HS256 JWT for session authentication.
 */
static std::string generate_token(const std::string& secret) {
    auto now = std::chrono::system_clock::now();
    return jwt::create()
        .set_issued_at(now)
        .set_expires_at(now + std::chrono::seconds(JWT_EXPIRY_SECONDS))
        .sign(jwt::algorithm::hs256{secret});
}

/**
 * Validate a JWT string. Returns true if the token is valid and not expired.
 */
static bool validate_token(const std::string& token, const std::string& secret) {
    try {
        auto decoded = jwt::decode(token);
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{secret})
            .leeway(5);
        verifier.verify(decoded);
        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Extract and validate a JWT from WebSocket subprotocols.
 * Looks for protocol strings of the form "access_token.<jwt>".
 * Returns the full protocol string if valid, empty string otherwise.
 */
static std::string validate_ws_token(const std::string& protocols,
                                     const std::string& secret) {
    // Protocols come as comma-separated list
    std::istringstream ss(protocols);
    std::string proto;
    while (std::getline(ss, proto, ',')) {
        // Trim whitespace
        auto start = proto.find_first_not_of(' ');
        if (start == std::string::npos) continue;
        proto = proto.substr(start);
        auto end = proto.find_last_not_of(' ');
        if (end != std::string::npos) proto = proto.substr(0, end + 1);

        const std::string prefix = "access_token.";
        if (proto.rfind(prefix, 0) == 0) {
            std::string jwt_str = proto.substr(prefix.size());
            if (validate_token(jwt_str, secret)) {
                return proto;
            }
        }
    }
    return "";
}

// ============================================================================
// METADATA
// ============================================================================

/**
 * Read [meta] section from deepgram.toml and return as JSON string.
 */
static std::string read_metadata() {
    auto data = toml::parse("deepgram.toml");
    if (!data.contains("meta")) {
        return "";
    }
    const auto& meta = toml::find(data, "meta");

    // Build a simple JSON object from the TOML table
    crow::json::wvalue json;
    for (const auto& [key, val] : meta.as_table()) {
        if (val.is_string()) {
            json[key] = val.as_string();
        } else if (val.is_integer()) {
            json[key] = val.as_integer();
        } else if (val.is_boolean()) {
            json[key] = val.as_boolean();
        } else if (val.is_array()) {
            // Convert array of strings to JSON array
            crow::json::wvalue arr;
            int idx = 0;
            for (const auto& elem : val.as_array()) {
                if (elem.is_string()) {
                    arr[idx++] = elem.as_string();
                }
            }
            json[key] = std::move(arr);
        }
    }
    return json.dump();
}

// ============================================================================
// DEEPGRAM WEBSOCKET CLIENT (Boost.Beast)
// ============================================================================

/**
 * DeepgramWSClient manages an outbound SSL WebSocket connection to Deepgram's
 * TTS API using Boost.Beast. It runs its own io_context on a dedicated thread
 * and provides callbacks for received messages and connection close events.
 *
 * Lifecycle:
 *   1. Construct with URL, API key, and callbacks
 *   2. Call connect() -- blocks until connected or fails
 *   3. Call send() to forward client messages to Deepgram
 *   4. Receive callbacks when Deepgram sends data back
 *   5. Call close() or let destructor clean up
 */
class DeepgramWSClient : public std::enable_shared_from_this<DeepgramWSClient> {
public:
    using MessageCallback = std::function<void(const std::string&, bool)>;
    using CloseCallback   = std::function<void()>;

    DeepgramWSClient(const std::string& url,
                     const std::string& api_key,
                     MessageCallback    on_message,
                     CloseCallback      on_close)
        : url_(url)
        , api_key_(api_key)
        , on_message_(std::move(on_message))
        , on_close_(std::move(on_close))
        , ioc_()
        , ssl_ctx_(ssl::context::tlsv12_client)
        , resolver_(net::make_strand(ioc_))
        , connected_(false)
        , closed_(false)
    {
        ssl_ctx_.set_default_verify_paths();
        ssl_ctx_.set_verify_mode(ssl::verify_none);
    }

    ~DeepgramWSClient() {
        close();
        if (io_thread_.joinable()) {
            io_thread_.join();
        }
    }

    /**
     * Establish connection to Deepgram. Returns true on success.
     */
    bool connect() {
        try {
            // Parse URL: wss://host/path?query
            std::string remaining = url_;
            // Strip wss://
            auto scheme_end = remaining.find("://");
            if (scheme_end != std::string::npos) {
                remaining = remaining.substr(scheme_end + 3);
            }
            // Split host and path+query
            auto path_start = remaining.find('/');
            host_ = remaining.substr(0, path_start);
            target_ = (path_start != std::string::npos)
                           ? remaining.substr(path_start)
                           : "/";

            ws_ = std::make_unique<
                websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(
                net::make_strand(ioc_), ssl_ctx_);

            // Resolve
            auto const results = resolver_.resolve(host_, "443");

            // TCP connect
            auto ep = beast::get_lowest_layer(*ws_).connect(results);

            // SNI hostname
            if (!SSL_set_tlsext_host_name(
                    ws_->next_layer().native_handle(), host_.c_str())) {
                return false;
            }

            // SSL handshake
            ws_->next_layer().handshake(ssl::stream_base::client);

            // WebSocket handshake with auth header
            std::string host_header = host_ + ":443";
            ws_->set_option(websocket::stream_base::decorator(
                [this](websocket::request_type& req) {
                    req.set(beast::http::field::authorization,
                            "Token " + api_key_);
                    req.set(beast::http::field::user_agent,
                            "deepgram-cpp-live-tts/1.0");
                }));

            ws_->handshake(host_header, target_);
            connected_ = true;

            // Start reading in background thread
            io_thread_ = std::thread([self = shared_from_this()]() {
                self->read_loop();
            });

            return true;
        } catch (const std::exception& e) {
            std::cerr << "Deepgram connection failed: " << e.what() << "\n";
            return false;
        }
    }

    /**
     * Send a message to Deepgram. binary=true for binary frames.
     */
    void send(const std::string& data, bool binary) {
        std::lock_guard<std::mutex> lock(write_mutex_);
        if (!connected_ || closed_) return;
        try {
            ws_->binary(binary);
            ws_->write(net::buffer(data));
        } catch (const std::exception& e) {
            std::cerr << "Error sending to Deepgram: " << e.what() << "\n";
        }
    }

    /**
     * Close the Deepgram connection.
     */
    void close() {
        std::lock_guard<std::mutex> lock(write_mutex_);
        if (closed_ || !connected_) return;
        closed_ = true;
        try {
            // Cancel the underlying socket to interrupt the read_loop
            // instead of calling ws_->close() which asserts if read is active
            beast::get_lowest_layer(*ws_).cancel();
        } catch (...) {
            // Connection may already be closed
        }
    }

    bool is_connected() const { return connected_ && !closed_; }

private:
    void read_loop() {
        try {
            while (connected_ && !closed_) {
                beast::flat_buffer buffer;
                ws_->read(buffer);

                bool is_binary = ws_->got_binary();
                std::string data(
                    static_cast<const char*>(buffer.data().data()),
                    buffer.data().size());

                if (on_message_) {
                    on_message_(data, is_binary);
                }
            }
        } catch (const beast::system_error& se) {
            if (se.code() != websocket::error::closed) {
                std::cerr << "Deepgram read error: " << se.what() << "\n";
            }
        } catch (const std::exception& e) {
            std::cerr << "Deepgram read error: " << e.what() << "\n";
        }

        connected_ = false;
        if (on_close_) {
            on_close_();
        }
    }

    std::string url_;
    std::string api_key_;
    std::string host_;
    std::string target_;
    MessageCallback on_message_;
    CloseCallback   on_close_;

    net::io_context ioc_;
    ssl::context    ssl_ctx_;
    tcp::resolver   resolver_;
    std::unique_ptr<websocket::stream<beast::ssl_stream<beast::tcp_stream>>> ws_;
    std::thread     io_thread_;
    std::mutex      write_mutex_;
    std::atomic<bool> connected_;
    std::atomic<bool> closed_;
};

// ============================================================================
// ACTIVE CONNECTIONS TRACKER
// ============================================================================

static std::mutex              connections_mutex;
static std::set<crow::websocket::connection*> active_connections;

static void track_connection(crow::websocket::connection* conn) {
    std::lock_guard<std::mutex> lock(connections_mutex);
    active_connections.insert(conn);
}

static void untrack_connection(crow::websocket::connection* conn) {
    std::lock_guard<std::mutex> lock(connections_mutex);
    active_connections.erase(conn);
}

// Map from crow WS connection to Deepgram client
static std::mutex deepgram_clients_mutex;
static std::unordered_map<crow::websocket::connection*,
                          std::shared_ptr<DeepgramWSClient>>
    deepgram_clients;

// ============================================================================
// URL HELPERS
// ============================================================================

/**
 * URL-encode a string for use in query parameters.
 */
static std::string url_encode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (char c : value) {
        if (std::isalnum(static_cast<unsigned char>(c)) ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2)
                    << static_cast<int>(static_cast<unsigned char>(c));
        }
    }
    return escaped.str();
}

/**
 * Build Deepgram TTS WebSocket URL with query parameters.
 */
static std::string build_deepgram_url(const std::string& base_url,
                                      const std::string& model,
                                      const std::string& encoding,
                                      const std::string& sample_rate,
                                      const std::string& container) {
    return base_url
        + "?model="       + url_encode(model)
        + "&encoding="    + url_encode(encoding)
        + "&sample_rate=" + url_encode(sample_rate)
        + "&container="   + url_encode(container);
}

/**
 * Extract a query parameter from a raw URL string. Returns fallback if missing.
 */
static std::string query_param(const std::string& url,
                               const std::string& key,
                               const std::string& fallback) {
    std::string search = key + "=";
    auto pos = url.find(search);
    if (pos == std::string::npos) return fallback;
    pos += search.size();
    auto end = url.find('&', pos);
    if (end == std::string::npos) end = url.size();
    return url.substr(pos, end - pos);
}

// ============================================================================
// MAIN
// ============================================================================

int main() {
    Config cfg = load_config();

    // Crow app with CORS middleware
    crow::App<crow::CORSHandler> app;

    auto& cors = app.get_middleware<crow::CORSHandler>();
    cors.global()
        .origin("*")
        .methods("GET"_method, "POST"_method, "OPTIONS"_method)
        .headers("Content-Type");

    // -----------------------------------------------------------------
    // GET /health
    // -----------------------------------------------------------------
    CROW_ROUTE(app, "/health")([]() {
        return crow::response(200, "OK");
    });

    // -----------------------------------------------------------------
    // GET /api/session - Issue JWT session token
    // -----------------------------------------------------------------
    CROW_ROUTE(app, "/api/session")([&cfg]() {
        try {
            std::string token = generate_token(cfg.session_secret);
            crow::json::wvalue resp;
            resp["token"] = token;
            auto r = crow::response(200, resp.dump());
            r.set_header("Content-Type", "application/json");
            return r;
        } catch (const std::exception& e) {
            crow::json::wvalue err;
            err["error"]   = "INTERNAL_SERVER_ERROR";
            err["message"] = "Failed to generate token";
            auto r = crow::response(500, err.dump());
            r.set_header("Content-Type", "application/json");
            return r;
        }
    });

    // -----------------------------------------------------------------
    // GET /api/metadata - Project metadata from deepgram.toml
    // -----------------------------------------------------------------
    CROW_ROUTE(app, "/api/metadata")([]() {
        try {
            std::string json_str = read_metadata();
            if (json_str.empty()) {
                crow::json::wvalue err;
                err["error"]   = "INTERNAL_SERVER_ERROR";
                err["message"] = "Missing [meta] section in deepgram.toml";
                auto r = crow::response(500, err.dump());
                r.set_header("Content-Type", "application/json");
                return r;
            }
            auto r = crow::response(200, json_str);
            r.set_header("Content-Type", "application/json");
            return r;
        } catch (const std::exception& e) {
            crow::json::wvalue err;
            err["error"]   = "INTERNAL_SERVER_ERROR";
            err["message"] = std::string("Failed to read metadata: ") + e.what();
            auto r = crow::response(500, err.dump());
            r.set_header("Content-Type", "application/json");
            return r;
        }
    });

    // -----------------------------------------------------------------
    // WS /api/live-text-to-speech - WebSocket proxy to Deepgram TTS
    // -----------------------------------------------------------------
    CROW_WEBSOCKET_ROUTE(app, "/api/live-text-to-speech")
        .mirrorprotocols()
        .onaccept([&cfg](const crow::request& req, void** userdata) -> bool {
            std::string protocols =
                std::string(req.get_header_value("Sec-WebSocket-Protocol"));
            std::string valid_proto =
                validate_ws_token(protocols, cfg.session_secret);

            if (valid_proto.empty()) {
                CROW_LOG_WARNING
                    << "WebSocket auth failed: invalid or missing token";
                return false;
            }

            // Store query string for onopen
            auto qpos = req.raw_url.find('?');
            std::string qs = (qpos != std::string::npos) ? req.raw_url.substr(qpos) : "";
            *userdata = new std::string(qs);
            return true;
        })
        .onopen([&cfg](crow::websocket::connection& conn) {
            CROW_LOG_INFO << "Client connected to /api/live-text-to-speech";
            track_connection(&conn);

            // Retrieve stored query string
            auto* qs_ptr = static_cast<std::string*>(conn.userdata());
            std::string url = "/api/live-text-to-speech" + (qs_ptr ? *qs_ptr : "");
            delete qs_ptr;
            conn.userdata(nullptr);

            // Parse query parameters from the upgrade URL
            std::string model       = query_param(url, "model", "aura-asteria-en");
            std::string encoding    = query_param(url, "encoding", "linear16");
            std::string sample_rate = query_param(url, "sample_rate", "24000");
            std::string container   = query_param(url, "container", "none");

            // Build Deepgram WebSocket URL
            std::string deepgram_url = build_deepgram_url(
                cfg.deepgram_tts_url, model, encoding, sample_rate, container);

            CROW_LOG_INFO << "Connecting to Deepgram TTS: model=" << model
                          << ", encoding=" << encoding
                          << ", sample_rate=" << sample_rate;

            // Create outbound Deepgram connection
            auto dg_client = std::make_shared<DeepgramWSClient>(
                deepgram_url,
                cfg.deepgram_api_key,
                // on_message: forward Deepgram -> Client
                [&conn](const std::string& data, bool is_binary) {
                    try {
                        if (is_binary) {
                            conn.send_binary(data);
                        } else {
                            conn.send_text(data);
                        }
                    } catch (const std::exception& e) {
                        CROW_LOG_ERROR
                            << "Error forwarding to client: " << e.what();
                    }
                },
                // on_close: notify client that Deepgram disconnected
                [&conn]() {
                    CROW_LOG_INFO << "Deepgram connection closed";
                    try {
                        conn.close("Deepgram disconnected");
                    } catch (...) {}
                });

            if (!dg_client->connect()) {
                CROW_LOG_ERROR << "Failed to connect to Deepgram TTS API";
                conn.close("Deepgram connection failed");
                untrack_connection(&conn);
                return;
            }

            CROW_LOG_INFO << "Connected to Deepgram TTS API";

            // Store the client mapping
            {
                std::lock_guard<std::mutex> lock(deepgram_clients_mutex);
                deepgram_clients[&conn] = dg_client;
            }
        })
        .onmessage([](crow::websocket::connection& conn,
                       const std::string& data, bool is_binary) {
            // Forward Client -> Deepgram
            std::shared_ptr<DeepgramWSClient> dg_client;
            {
                std::lock_guard<std::mutex> lock(deepgram_clients_mutex);
                auto it = deepgram_clients.find(&conn);
                if (it != deepgram_clients.end()) {
                    dg_client = it->second;
                }
            }

            if (dg_client && dg_client->is_connected()) {
                dg_client->send(data, is_binary);
            }
        })
        .onclose([](crow::websocket::connection& conn,
                     const std::string& reason, uint16_t) {
            CROW_LOG_INFO << "Client disconnected: " << reason;
            untrack_connection(&conn);

            // Close corresponding Deepgram connection
            std::shared_ptr<DeepgramWSClient> dg_client;
            {
                std::lock_guard<std::mutex> lock(deepgram_clients_mutex);
                auto it = deepgram_clients.find(&conn);
                if (it != deepgram_clients.end()) {
                    dg_client = it->second;
                    deepgram_clients.erase(it);
                }
            }

            if (dg_client) {
                dg_client->close();
            }

            CROW_LOG_INFO << "WebSocket proxy session ended";
        });

    // -----------------------------------------------------------------
    // Start the Crow server
    // -----------------------------------------------------------------
    std::string separator(70, '=');
    CROW_LOG_INFO << separator;
    CROW_LOG_INFO << "Backend API Server running at http://localhost:"
                  << cfg.port;
    CROW_LOG_INFO << "";
    CROW_LOG_INFO << "GET  /api/session";
    CROW_LOG_INFO << "WS   /api/live-text-to-speech (auth required)";
    CROW_LOG_INFO << "GET  /api/metadata";
    CROW_LOG_INFO << "GET  /health";
    CROW_LOG_INFO << separator;

    app.bindaddr(cfg.host)
       .port(cfg.port)
       .multithreaded()
       .run();

    return 0;
}
