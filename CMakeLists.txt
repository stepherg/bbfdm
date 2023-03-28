cmake_minimum_required(VERSION 3.0)

PROJECT(bbf C)

OPTION(BBFD_ENABLED "build bbfd daemon with their dependencies" OFF)

add_subdirectory(libbbf_api)
add_subdirectory(libbbf_dm)

# add CPack to project
SET(CPACK_PACKAGE_NAME "libbbf")
SET(CPACK_PACKAGE_VENDOR "iopsys.io")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "libbbf - Datamodel library")
SET(CPACK_PACKAGE_VERSION "1.0.0")
SET(CPACK_GENERATOR STGZ)

include(CPack)
