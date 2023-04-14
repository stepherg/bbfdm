cmake_minimum_required(VERSION 3.0)

PROJECT(bbf C)

OPTION(BBFDMD_ENABLED "build bbfdmd daemon with their dependencies" OFF)

add_subdirectory(libbbf_api)
add_subdirectory(libbbf_dm)

IF(BBFDMD_ENABLED)
	add_subdirectory(bbfdmd/src)
ENDIF(BBFDMD_ENABLED)
