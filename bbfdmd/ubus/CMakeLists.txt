cmake_minimum_required(VERSION 3.0)

PROJECT(bbfdmd)

ADD_DEFINITIONS(-fstrict-aliasing -Wall -Wextra -Werror -Wformat -Wformat-signedness -g3 -fPIC -D_GNU_SOURCE)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_SOURCE_DIR}")

FILE(GLOB BBF_SOURCES *.c)
ADD_EXECUTABLE(bbfdmd ${BBF_SOURCES})
TARGET_LINK_LIBRARIES(bbfdmd ubus ubox blobmsg_json json-c bbfdm-api-v2)
INSTALL(TARGETS bbfdmd DESTINATION usr/sbin)
