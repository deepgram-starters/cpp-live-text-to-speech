cmake_minimum_required(VERSION 3.20)
project(cpp-live-text-to-speech LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find dependencies installed via vcpkg
find_package(Crow CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)
find_package(toml11 CONFIG REQUIRED)
find_package(jwt-cpp CONFIG REQUIRED)

add_executable(${PROJECT_NAME} src/main.cpp)

target_link_libraries(${PROJECT_NAME} PRIVATE
    Crow::Crow
    Boost::system
    OpenSSL::SSL
    OpenSSL::Crypto
    toml11::toml11
    jwt-cpp::jwt-cpp
)
