cmake_minimum_required(VERSION 3.0)

PROJECT(bbfdmd)

ADD_DEFINITIONS(-fstrict-aliasing -Wall -Wextra -Werror -Wformat -Wformat-signedness -fPIC -D_GNU_SOURCE)
ADD_DEFINITIONS(-DBBF_VENDOR_PREFIX="${BBF_VENDOR_PREFIX}")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_SOURCE_DIR} -I${CMAKE_SOURCE_DIR}/libbbfdm-api/")

IF(${BBFDMD_MAX_MSG_LEN})
	ADD_DEFINITIONS(-DBBFDM_MAX_MSG_LEN=${BBFDMD_MAX_MSG_LEN})
ENDIF()

OPTION(BBF_SCHEMA_FULL_TREE "build with schema full tree" OFF)

IF(BBF_SCHEMA_FULL_TREE)
	add_compile_definitions(BBF_SCHEMA_FULL_TREE)
ENDIF(BBF_SCHEMA_FULL_TREE)

FILE(GLOB BBF_SOURCES *.c)
ADD_EXECUTABLE(bbfdmd ${BBF_SOURCES})
TARGET_LINK_LIBRARIES(bbfdmd ubus ubox blobmsg_json dl bbfdm-api)
INSTALL(TARGETS bbfdmd DESTINATION usr/sbin)
INSTALL(FILES ../../json/input.json DESTINATION etc/bbfdm)
