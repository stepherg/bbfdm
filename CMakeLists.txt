cmake_minimum_required(VERSION 3.0)

PROJECT(bbf C)

OPTION(BBFD_ENABLED "build bbfd daemon with their dependencies" OFF)

add_subdirectory(libbbf_api)
add_subdirectory(libbbf_dm)
