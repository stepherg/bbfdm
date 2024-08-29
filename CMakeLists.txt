cmake_minimum_required(VERSION 3.0)

PROJECT(bbf C)

add_subdirectory(libbbfdm-api)
add_subdirectory(libbbfdm-ubus)
add_subdirectory(libbbfdm)
add_subdirectory(bbfdmd)

# Capture the environment variables
set(MY_CC "$ENV{CC}")
set(MY_CFLAGS "$ENV{CFLAGS}")
set(MY_LDFLAGS "$ENV{LDFLAGS}")

# Define a custom target to build the utilities using Makefile
add_custom_target(
    build_utilities
    COMMAND ${CMAKE_COMMAND} -E env
    	CC=${MY_CC}
        CFLAGS=${MY_CFLAGS}
        LDFLAGS=${MY_LDFLAGS}
        make
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/utilities
)

# Make bbfdmd target depend on the build_utilities target
add_dependencies(bbfdmd build_utilities)
