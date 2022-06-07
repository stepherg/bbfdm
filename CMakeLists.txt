cmake_minimum_required(VERSION 3.0)

PROJECT(bbf C)

ADD_DEFINITIONS(-Wall -Werror)
ADD_DEFINITIONS(-D_GNU_SOURCE)
ADD_DEFINITIONS(-DBBF_VENDOR_PREFIX="${BBF_VENDOR_PREFIX}")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I. -I./dmtree -I./dmtree/tr181 -I./dmtree/tr104 -I./dmtree/tr143")

OPTION(BBF_TR181 "build with tr181 datamodel" ON)
OPTION(BBF_TR104 "build with tr104 datamodel" ON)
OPTION(BBF_TR143 "build with tr143 datamodel" ON)
OPTION(BBF_DOTSO_PLUGIN "build with dotso plugin" ON)
OPTION(BBF_JSON_PLUGIN "build with json plugin" ON)
OPTION(BBF_VENDOR_EXTENSION "build with vendor extension enabled" ON)
OPTION(WITH_WOLFSSL "build with lib wolfssl" OFF)
OPTION(WITH_OPENSSL "build with lib openssl" OFF)
OPTION(WITH_MBEDTLS "build with lib mbedtls" OFF)

SET(BBF_API_SOURCES libbbf_api/dmbbf.c
					libbbf_api/dmubus.c
					libbbf_api/dmjson.c
					libbbf_api/dmuci.c
					libbbf_api/dmcommon.c
					libbbf_api/dmmem.c
					libbbf_api/dmapi.c)

SET(BBF_DM_SOURCES dmentry.c
				   dmdiagnostics.c
				   dmbbfcommon.c)

IF(BBF_TR181)
    SET(BBF_TR181_SOURCES dmtree/tr181/device.c
    					  dmtree/tr181/deviceinfo.c
    					  dmtree/tr181/managementserver.c
    					  dmtree/tr181/times.c
    					  dmtree/tr181/upnp.c
    					  dmtree/tr181/wifi.c
    					  dmtree/tr181/ethernet.c
    					  dmtree/tr181/atm.c
    					  dmtree/tr181/ptm.c
    					  dmtree/tr181/bridging.c
    					  dmtree/tr181/hosts.c
    					  dmtree/tr181/dhcpv4.c
    					  dmtree/tr181/ip.c
    					  dmtree/tr181/ppp.c
    					  dmtree/tr181/nat.c
    					  dmtree/tr181/routing.c
    					  dmtree/tr181/firewall.c
    					  dmtree/tr181/dns.c
    					  dmtree/tr181/users.c
    					  dmtree/tr181/dhcpv6.c
    					  dmtree/tr181/dsl.c
    					  dmtree/tr181/fast.c
    					  dmtree/tr181/interfacestack.c
    					  dmtree/tr181/usb.c
    					  dmtree/tr181/gre.c
    					  dmtree/tr181/dynamicdns.c
    					  dmtree/tr181/security.c
    					  dmtree/tr181/lanconfigsecurity.c
    					  dmtree/tr181/ieee1905.c
    					  dmtree/tr181/qos.c
    					  dmtree/tr181/routeradvertisement.c)
    add_compile_definitions(BBF_TR181)
ENDIF(BBF_TR181)

IF(BBF_TR104)
    SET(BBF_TR104_SOURCES dmtree/tr104/common.c
    					  dmtree/tr104/servicesvoiceservicecalllog.c
    					  dmtree/tr104/servicesvoiceservicesip.c
    					  dmtree/tr104/servicesvoiceservice.c
    					  dmtree/tr104/servicesvoiceservicecapabilities.c
    					  dmtree/tr104/servicesvoiceservicepots.c
    					  dmtree/tr104/servicesvoiceservicevoipprofile.c
    					  dmtree/tr104/servicesvoiceservicecallcontrol.c
    					  dmtree/tr104/servicesvoiceservicecodecprofile.c
    					  dmtree/tr104/servicesvoiceservicereservedports.c
    					  dmtree/tr104/servicesvoiceservicedect.c)
    add_compile_definitions(BBF_TR104)
ENDIF(BBF_TR104)

IF(BBF_TR143)
    SET(BBF_TR143_SOURCES dmtree/tr143/diagnostics.c)
    add_compile_definitions(BBF_TR143)
ENDIF(BBF_TR143)

IF(BBF_DOTSO_PLUGIN)
    SET(BBF_DOTSO_PLUGIN_SOURCES dmdynamiclibrary.c)
    add_compile_definitions(BBFDM_ENABLE_DOTSO_PLUGIN)
ENDIF(BBF_DOTSO_PLUGIN)

IF(BBF_JSON_PLUGIN)
    SET(BBF_JSON_PLUGIN_SOURCES dmdynamicjson.c)
    add_compile_definitions(BBFDM_ENABLE_JSON_PLUGIN)
endif(BBF_JSON_PLUGIN)

IF(WITH_WOLFSSL)
	SET(SSL_LIBS wolfssl)
	SET(CRYPTO_LIBS crypto)
	add_compile_definitions(LWOLFSSL)
ENDIF(WITH_WOLFSSL)

IF(WITH_OPENSSL)
	SET(SSL_LIBS ssl)
	SET(CRYPTO_LIBS crypto)
	add_compile_definitions(LOPENSSL)
ENDIF(WITH_OPENSSL)

IF(WITH_MBEDTLS)
	SET(SSL_LIBS mbedtls)
	SET(CRYPTO_LIBS mbedcrypto)
	add_compile_definitions(LMBEDTLS)
ENDIF(WITH_MBEDTLS)

IF(BBF_VENDOR_EXTENSION)
	SET(BBF_VENDOR_EXTENSION_SOURCES dmdynamicvendor.c dmtree/vendor/vendor.c)
	ADD_DEFINITIONS(-DBBF_VENDOR_LIST="${BBF_VENDOR_LIST}")
	add_compile_definitions(BBF_VENDOR_EXTENSION)

	SET(BBF_VENDOR_LIST "iopsys" CACHE STRING "vendor list to be used")

	IF(BBF_VENDOR_LIST MATCHES "(.*)iopsys(.*)")
		add_compile_definitions(BBF_VENDOR_IOPSYS)

		IF(BBF_TR181)
			SET(BBF_VENDOR_IOPSYS_TR181_SOURCES dmtree/vendor/iopsys/tr181/vendor.c
												dmtree/vendor/iopsys/tr181/device.c
												dmtree/vendor/iopsys/tr181/deviceinfo.c
												dmtree/vendor/iopsys/tr181/bridging.c
												dmtree/vendor/iopsys/tr181/ethernet.c
												dmtree/vendor/iopsys/tr181/times.c
												dmtree/vendor/iopsys/tr181/x_iopsys_eu_igmp.c
												dmtree/vendor/iopsys/tr181/x_iopsys_eu_mld.c)
		ENDIF(BBF_TR181)

		IF(BBF_TR104)
			SET(BBF_VENDOR_IOPSYS_TR104_SOURCES dmtree/vendor/iopsys/tr104/servicesvoiceservicecallcontrol.c
												dmtree/vendor/iopsys/tr104/servicesvoiceservicecalllog.c
												dmtree/vendor/iopsys/tr104/servicesvoiceservicedect.c)
		ENDIF(BBF_TR104)

	ENDIF(BBF_VENDOR_LIST MATCHES "(.*)iopsys(.*)")

	IF(BBF_VENDOR_LIST MATCHES "(.*)openwrt(.*)")
		add_compile_definitions(BBF_VENDOR_OPENWRT)

		IF(BBF_TR181)
			SET(BBF_VENDOR_OPENWRT_TR181_SOURCES dmtree/vendor/openwrt/tr181/vendor.c
												 dmtree/vendor/openwrt/tr181/deviceinfo.c
												 dmtree/vendor/openwrt/tr181/qos.c)
		ENDIF(BBF_TR181)

	ENDIF(BBF_VENDOR_LIST MATCHES "(.*)openwrt(.*)")
	
	IF(BBF_VENDOR_LIST MATCHES "(.*)test(.*)")
		add_compile_definitions(BBF_VENDOR_TEST)

		IF(BBF_TR181)
			SET(BBF_VENDOR_TEST_TR181_SOURCES dmtree/vendor/test/tr181/vendor.c
											  dmtree/vendor/test/tr181/deviceinfo.c
											  dmtree/vendor/test/tr181/firewall.c
											  dmtree/vendor/test/tr181/device.c
											  dmtree/vendor/test/tr181/x_test_com_dropbear.c)
		ENDIF(BBF_TR181)

	ENDIF(BBF_VENDOR_LIST MATCHES "(.*)test(.*)")

ENDIF(BBF_VENDOR_EXTENSION)

ADD_LIBRARY(bbfdm SHARED ${BBF_API_SOURCES} ${BBF_DM_SOURCES}
						 ${BBF_TR181_SOURCES} ${BBF_TR104_SOURCES} ${BBF_TR143_SOURCES}
						 ${BBF_DOTSO_PLUGIN_SOURCES} ${BBF_JSON_PLUGIN_SOURCES} ${BBF_VENDOR_EXTENSION_SOURCES}
						 ${BBF_VENDOR_IOPSYS_TR181_SOURCES} ${BBF_VENDOR_IOPSYS_TR104_SOURCES}
						 ${BBF_VENDOR_OPENWRT_TR181_SOURCES}
						 ${BBF_VENDOR_TEST_TR181_SOURCES})

TARGET_LINK_LIBRARIES(bbfdm uci ubus ubox json-c blobmsg_json trace dl curl ${SSL_LIBS} ${CRYPTO_LIBS})

INSTALL(TARGETS bbfdm
		LIBRARY DESTINATION "/usr/lib")

INSTALL(DIRECTORY DESTINATION "/etc/bbfdm")
INSTALL(DIRECTORY DESTINATION "/etc/bbfdm/dmmap")
INSTALL(DIRECTORY DESTINATION "/etc/bbfdm/json")
INSTALL(DIRECTORY DESTINATION "/usr/share/bbfdm")
INSTALL(DIRECTORY DESTINATION "/usr/lib/bbfdm")

FILE(GLOB headers include/*.h)
INSTALL(FILES ${headers}
	DESTINATION include
)

FILE(GLOB libbbf_api_headers libbbf_api/*.h)
INSTALL(FILES ${libbbf_api_headers}
	DESTINATION include/libbbf_api
)

FILE(GLOB libbbfdm_headers *.h)
INSTALL(FILES ${libbbfdm_headers}
	DESTINATION include/libbbfdm
)

FILE(GLOB scripts scripts/*)
INSTALL(FILES ${scripts}
	DESTINATION "/usr/share/bbfdm"
)
