cmake_minimum_required(VERSION 3.15)
project(vpn_server)
# set(CMAKE_VERBOSE_MAKEFILE ON)
set(server vpn_server)
set(lib vpn)
set(ssl_prefix /usr/local/mbedtls_3.3.0)

file(GLOB lib_files src/*.c)

add_library(${lib} STATIC)
target_sources(${lib} PRIVATE ${lib_files})
target_compile_definitions(${lib} PRIVATE __USE_GNU _GNU_SOURCE)
target_include_directories(${lib} PRIVATE inc internal ${ssl_prefix}/include)
target_link_libraries(${lib} PRIVATE pthread mbedcrypto mbedtls mbedx509)
target_link_directories(${lib} PRIVATE ${ssl_prefix}/lib)

add_executable(${server} example/main_ssl.c)

target_include_directories(${server} PRIVATE inc)

target_link_libraries(${server} PRIVATE ${lib})

file(GLOB test_files test/*.cpp test/*.cc)
add_executable(test ${test_files})
target_include_directories(test PRIVATE inc /usr/local/googletest/include)
target_link_libraries(test PRIVATE gtest gtest_main ${lib})
target_link_directories(test PRIVATE /usr/local/googletest/lib)
