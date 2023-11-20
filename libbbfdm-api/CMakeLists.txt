cmake_minimum_required(VERSION 3.0)

PROJECT(libbbfdm-api)

ADD_DEFINITIONS(-Wall -Werror)
ADD_DEFINITIONS(-D_GNU_SOURCE)
ADD_DEFINITIONS(-DBBF_VENDOR_PREFIX="${BBF_VENDOR_PREFIX}")

IF(${BBF_MAX_OBJECT_INSTANCES})
	ADD_DEFINITIONS(-DBBF_MAX_OBJECT_INSTANCES=${BBF_MAX_OBJECT_INSTANCES})
ENDIF()

OPTION(BBF_VENDOR_EXTENSION "build with vendor extension enabled" ON)
OPTION(BBF_SCHEMA_FULL_TREE "build with schema full tree" OFF)

SET(BBF_PLUGIN_SOURCES plugin/dotso_plugin.c plugin/json_plugin.c)

IF(BBF_VENDOR_EXTENSION)
	SET(BBF_VENDOR_EXTENSION_SOURCES plugin/vendor_plugin.c)
	ADD_DEFINITIONS(-DBBF_VENDOR_LIST="${BBF_VENDOR_LIST}")
	add_compile_definitions(BBF_VENDOR_EXTENSION)
	SET(BBF_VENDOR_LIST "iopsys" CACHE STRING "vendor list to be used")
	STRING(REPLACE "," ";" VENDOR_LIST ${BBF_VENDOR_LIST})
ENDIF(BBF_VENDOR_EXTENSION)

IF(BBF_SCHEMA_FULL_TREE)
	add_compile_definitions(BBF_SCHEMA_FULL_TREE)
ENDIF(BBF_SCHEMA_FULL_TREE)

FILE(GLOB BBF_API_SOURCES *.c)

ADD_LIBRARY(bbfdm-api SHARED ${BBF_API_SOURCES} ${BBF_PLUGIN_SOURCES} ${BBF_VENDOR_EXTENSION_SOURCES})

TARGET_LINK_LIBRARIES(bbfdm-api uci ubus ubox json-c blobmsg_json dl)

INSTALL(TARGETS bbfdm-api
		LIBRARY DESTINATION usr/lib)

FILE(GLOB libbbfdm-api_headers *.h)
INSTALL(FILES ${libbbfdm-api_headers}
	DESTINATION usr/include/libbbfdm-api
)

FILE(GLOB libbbfdm-api_include_headers include/*.h)
INSTALL(FILES ${libbbfdm-api_include_headers}
	DESTINATION usr/include
)
