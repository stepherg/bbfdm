cmake_minimum_required(VERSION 3.0)

PROJECT(bbfdmd C)

OPTION(DM_ENABLE_UBUS "Build with UBus Support" ON)

IF(DM_ENABLE_UBUS)
        add_subdirectory(ubus)
ENDIF(DM_ENABLE_UBUS)
