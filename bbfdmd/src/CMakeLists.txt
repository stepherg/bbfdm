cmake_minimum_required(VERSION 3.0)

PROJECT(bbfdmd)

ADD_DEFINITIONS(-fstrict-aliasing -Wall -Wextra -Werror -Wformat -Wformat-signedness -fPIC -D_GNU_SOURCE)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_SOURCE_DIR}")

IF(${BBFDMD_MAX_MSG_LEN})
	ADD_DEFINITIONS(-DUSPD_MAX_MSG_LEN=${BBFDMD_MAX_MSG_LEN})
ENDIF()

FILE(GLOB BBF_SOURCES *.c)
ADD_EXECUTABLE(bbfdmd ${BBF_SOURCES})
TARGET_LINK_LIBRARIES(bbfdmd uci ubus ubox blobmsg_json bbfdm-api bbfdm)
INSTALL(TARGETS bbfdmd DESTINATION usr/sbin)
