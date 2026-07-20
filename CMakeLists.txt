# CMake preset for the airfn usermode client only.
# The driver + mapper still build via physmem.sln (MSBuild + WDK).
# This preset exists so CI can build the client without needing WDK.

cmake_minimum_required(VERSION 3.24)
project(airfn LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (MSVC)
    add_compile_options(/W4 /permissive- /Zc:preprocessor /MP)
    add_compile_definitions(WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
endif()

add_executable(airfn
    airfn/main.cpp
    airfn/engine/uworld.cpp
    airfn/engine/gnames.cpp
    airfn/engine/gobjects.cpp
    "api/driver/driver_um_lib.cpp"
)

target_include_directories(airfn PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/api
)

set_target_properties(airfn PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
