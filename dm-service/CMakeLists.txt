cmake_minimum_required(VERSION 3.0)

PROJECT(dm-service C)

ADD_DEFINITIONS(-fstrict-aliasing -Wall -Wextra -Werror -Wformat -Wformat-signedness -fPIC -D_GNU_SOURCE)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_SOURCE_DIR} -I${CMAKE_SOURCE_DIR}/libbbfdm-api/ -I${CMAKE_SOURCE_DIR}/libbbfdm-ubus/")

FILE(GLOB BBF_SOURCES *.c)
ADD_EXECUTABLE(dm-service ${BBF_SOURCES})
TARGET_LINK_LIBRARIES(dm-service bbfdm-ubus)
INSTALL(TARGETS dm-service DESTINATION usr/sbin)