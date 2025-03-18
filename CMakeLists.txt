cmake_minimum_required(VERSION 2.8)
project(loopback)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "-std=c++11 -O3")
add_definitions(-DVERSION="1.0.4")

add_executable(loopback main.cpp main.h src/common.cpp src/common.h src/bitcalc.cpp)
target_link_libraries(loopback pthread)
target_link_libraries(loopback pcap)
