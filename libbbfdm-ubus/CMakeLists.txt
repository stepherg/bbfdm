cmake_minimum_required(VERSION 3.0)

PROJECT(libbbfdm-ubus)

ADD_DEFINITIONS(-Wall -Werror -g -D_GNU_SOURCE)
ADD_DEFINITIONS(-DBBF_VENDOR_PREFIX="${BBF_VENDOR_PREFIX}")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_SOURCE_DIR} -I${CMAKE_SOURCE_DIR}/libbbfdm-api/")

IF(${BBFDMD_MAX_MSG_LEN})
	ADD_DEFINITIONS(-DBBFDM_MAX_MSG_LEN=${BBFDMD_MAX_MSG_LEN})
ENDIF()

OPTION(BBF_SCHEMA_FULL_TREE "build with schema full tree" OFF)

IF(BBF_SCHEMA_FULL_TREE)
	add_compile_definitions(BBF_SCHEMA_FULL_TREE)
ENDIF(BBF_SCHEMA_FULL_TREE)

FILE(GLOB BBF_UBUS_SOURCES *.c)

ADD_LIBRARY(bbfdm-ubus SHARED ${BBF_UBUS_SOURCES})

TARGET_LINK_LIBRARIES(bbfdm-ubus uci ubus ubox json-c blobmsg_json bbfdm-api)

INSTALL(TARGETS bbfdm-ubus
		LIBRARY DESTINATION usr/lib)

FILE(GLOB libbbfdm-ubus_headers bbfdm-ubus.h)
INSTALL(FILES ${libbbfdm-ubus_headers}
	DESTINATION usr/include/libbbfdm-ubus
)
