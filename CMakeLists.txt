project(ping C)
cmake_minimum_required(VERSION 3.1)

add_executable(ping src/ping.c)
set_target_properties(ping PROPERTIES C_STANDARD 90)

target_compile_definitions(ping PRIVATE "$<$<CONFIG:Debug>:DEBUG>")

if(WIN32)
    target_link_libraries(ping ws2_32)
endif()
