cmake_minimum_required(VERSION 3.0)

PROJECT(libbbfdm-api-version-2)

ADD_DEFINITIONS(-Wall -Werror -g -D_GNU_SOURCE)

FILE(GLOB BBFDM_API_SOURCES *.c)

ADD_LIBRARY(bbfdm-api-v2 SHARED ${BBFDM_API_SOURCES})

TARGET_LINK_LIBRARIES(bbfdm-api-v2 uci ubus)

INSTALL(TARGETS bbfdm-api-v2
		LIBRARY DESTINATION usr/lib)

FILE(GLOB libbbfdm-api-v2_headers *.h)
INSTALL(FILES ${libbbfdm-api-v2_headers}
	DESTINATION usr/include/libbbfdm-api
)

FILE(GLOB libbbfdm-api-v2_headers *.h)
INSTALL(FILES ${libbbfdm-api-v2_headers}
	DESTINATION usr/include/libbbfdm-api/version-2
)
