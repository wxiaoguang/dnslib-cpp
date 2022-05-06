cmake_minimum_required(VERSION 3.0)
project(dnslib)

set(CMAKE_CXX_STANDARD 11)

set(SOURCES dnslib/buffer.cpp dnslib/message.cpp dnslib/rr.cpp dnslib/qs.cpp)

add_library (dnslib ${SOURCES})
target_compile_options(dnslib PUBLIC -Werror -Wall -Wextra)

add_executable (unittests dnslib/unittests.cpp)
target_compile_options(unittests PUBLIC -Werror -Wall -Wextra)
target_link_libraries (unittests dnslib)

add_executable (fakesrv dnslib/fakesrv.cpp)
target_link_libraries (fakesrv dnslib)

add_executable (fakecli dnslib/fakecli.cpp)
target_link_libraries (fakecli dnslib)
