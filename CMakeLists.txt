project(ping)
cmake_minimum_required(VERSION 3.0)

add_executable(ping src/ping.c)

if(CMAKE_COMPILER_IS_GNUCC)
    target_compile_options(ping PRIVATE -Wall)
endif()
