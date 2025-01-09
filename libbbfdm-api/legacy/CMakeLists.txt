cmake_minimum_required(VERSION 3.0)

PROJECT(libbbfdm-api-legacy)

ADD_DEFINITIONS(-Wall -Werror -g -D_GNU_SOURCE)
ADD_DEFINITIONS(-DBBF_VENDOR_PREFIX="${BBF_VENDOR_PREFIX}")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_SOURCE_DIR}")

IF(${BBF_MAX_OBJECT_INSTANCES})
	ADD_DEFINITIONS(-DBBF_MAX_OBJECT_INSTANCES=${BBF_MAX_OBJECT_INSTANCES})
ENDIF()

OPTION(BBF_SCHEMA_FULL_TREE "build with schema full tree" OFF)

IF(BBF_SCHEMA_FULL_TREE)
	add_compile_definitions(BBF_SCHEMA_FULL_TREE)
ENDIF(BBF_SCHEMA_FULL_TREE)

FILE(GLOB BBF_API_SOURCES *.c plugin/*.c)

ADD_LIBRARY(bbfdm-api SHARED ${BBF_API_SOURCES})

TARGET_LINK_LIBRARIES(bbfdm-api uci ubus ubox json-c blobmsg_json dl curl bbfdm-api-v2)

INSTALL(TARGETS bbfdm-api
		LIBRARY DESTINATION usr/lib)

FILE(GLOB libbbfdm-api_headers *.h)
INSTALL(FILES ${libbbfdm-api_headers}
	DESTINATION usr/include/libbbfdm-api
)

FILE(GLOB libbbfdm-api_headers *.h)
INSTALL(FILES ${libbbfdm-api_headers}
	DESTINATION usr/include/libbbfdm-api/legacy
)

FILE(GLOB libbbfdm-api_include_headers include/*.h)
INSTALL(FILES ${libbbfdm-api_include_headers}
	DESTINATION usr/include
)
