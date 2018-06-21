cmake_minimum_required(VERSION 2.8)

project(DHT)

set(SOURCES
    main.cpp /
    sha1.cpp)

set(HEADER_FILES
    sha1.hpp)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADER_FILES})
