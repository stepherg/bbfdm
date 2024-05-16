cmake_minimum_required(VERSION 3.0)

PROJECT(libbbfdm)

ADD_DEFINITIONS(-Wall -Werror -D_GNU_SOURCE)
ADD_DEFINITIONS(-DBBF_VENDOR_PREFIX="${BBF_VENDOR_PREFIX}")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_SOURCE_DIR} -I${CMAKE_CURRENT_SOURCE_DIR} -I${CMAKE_CURRENT_SOURCE_DIR}/dmtree")

OPTION(BBF_TR181 "build with tr181 datamodel" ON)
OPTION(BBF_WIFI_DATAELEMENTS "build with wifi dataelements datamodel" ON)

SET(BBF_DM_SOURCES dmlayer.c)

IF(BBF_TR181)
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_CURRENT_SOURCE_DIR}/dmtree/tr181")
	FILE(GLOB BBF_TR181_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/dmtree/tr181/*.c)
	add_compile_definitions(BBF_TR181)
	IF(BBF_WIFI_DATAELEMENTS)
		add_compile_definitions(BBF_WIFI_DATAELEMENTS)
	ENDIF(BBF_WIFI_DATAELEMENTS)
ENDIF(BBF_TR181)

ADD_LIBRARY(bbfdm SHARED ${BBF_DM_SOURCES} ${BBF_TR181_SOURCES})

TARGET_LINK_LIBRARIES(bbfdm uci ubus ubox json-c blobmsg_json m bbfdm-api ssl crypto)

INSTALL(TARGETS bbfdm
		LIBRARY DESTINATION usr/share/bbfdm)

INSTALL(TARGETS bbfdm
		LIBRARY DESTINATION usr/lib)

INSTALL(DIRECTORY DESTINATION etc/bbfdm)
INSTALL(DIRECTORY DESTINATION etc/bbfdm/dmmap)
INSTALL(DIRECTORY DESTINATION usr/share/bbfdm/plugins)

INSTALL(DIRECTORY DESTINATION usr/share/bbfdm)
INSTALL(DIRECTORY DESTINATION usr/libexec/rpcd)
FILE(GLOB scripts scripts/*)

FOREACH(script ${scripts})
	IF(IS_DIRECTORY ${script})
		INSTALL(DIRECTORY ${script}
			DESTINATION usr/share/bbfdm/scripts
		)
	ELSE()
		INSTALL(FILES ${script}
			PERMISSIONS OWNER_EXECUTE
			DESTINATION usr/share/bbfdm/scripts
		)
	ENDIF()
ENDFOREACH()

INSTALL(FILES scripts/bbf.diag
	PERMISSIONS OWNER_EXECUTE
	DESTINATION usr/libexec/rpcd
)

string(REPLACE "," ";" VENDOR_LIST ${BBF_VENDOR_LIST})

foreach(VENDOR ${VENDOR_LIST})
    add_subdirectory(dmtree/vendor/${VENDOR})
endforeach()
