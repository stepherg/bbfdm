cmake_minimum_required(VERSION 3.0)

PROJECT(bbfd)

ADD_DEFINITIONS(-fstrict-aliasing -Wall -Wextra -Werror -Wformat -Wformat-signedness -fPIC -D_GNU_SOURCE)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_SOURCE_DIR}")

IF(${BBFD_MAX_MSG_LEN})
	ADD_DEFINITIONS(-DUSPD_MAX_MSG_LEN=${BBFD_MAX_MSG_LEN})
ENDIF()

FILE(GLOB BBF_SOURCES *.c)
ADD_EXECUTABLE(bbfd ${BBF_SOURCES})
TARGET_LINK_LIBRARIES(bbfd uci ubus ubox blobmsg_json bbf_api bbf_dm)
INSTALL(TARGETS bbfd DESTINATION usr/sbin)
