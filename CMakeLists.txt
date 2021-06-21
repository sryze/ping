project(ping C)
cmake_minimum_required(VERSION 3.0)

add_executable(ping src/ping.c)
target_compile_definitions(ping PRIVATE "$<$<CONFIG:Debug>:DEBUG>")

if(CMAKE_COMPILER_IS_GNUCC)
    target_compile_options(ping PRIVATE -Wall)
endif()

if(WIN32)
    target_link_libraries(ping ws2_32)
endif()
