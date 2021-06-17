lib_LTLIBRARIES = libbbf_api.la

libbbf_api_la_SOURCES =				\
	../libbbf_api/dmbbf.c			\
	../libbbf_api/dmubus.c			\
	../libbbf_api/dmjson.c			\
	../libbbf_api/dmuci.c			\
	../libbbf_api/dmcommon.c 		\
	../libbbf_api/dmmem.c

libbbf_api_la_CFLAGS =		\
	$(AM_CFLAGS)			\
	$(LIBUCI_CFLAGS)		\
	$(LIBUBOX_CFLAGS)		\
	$(LIBUBUS_CFLAGS) 		\
	-Wall

libbbf_api_la_LDFLAGS = 	\
	$(AM_LDFLAGS)			\
	$(LIBUCI_LDFLAGS)		\
	$(LIBUBOX_LDFLAGS)		\
	$(LIBUBUS_LDFLAGS)

libbbf_api_la_LIBADD =		\
	$(AM_LIBS)				\
	$(LIBUCI_LIBS)			\
	$(LIBUBOX_LIBS)			\
	$(LIBUBUS_LIBS)			\
	$(LIBJSON_LIBS)			\
	$(LBLOBMSG_LIBS)

lib_LTLIBRARIES += libbbfdm.la

libbbfdm_la_SOURCES =	\
	../dmentry.c 		\
	../dmdynamiclibrary.c \
	../dmdynamicjson.c 	\
	../dmmemjson.c 		\
	../dmoperate.c		\
	../dmdiagnostics.c	\
	../dmbbfcommon.c

if BBF_TR181
libbbfdm_la_SOURCES +=							\
	../dmtree/tr181/device.c					\
	../dmtree/tr181/deviceinfo.c				\
	../dmtree/tr181/managementserver.c			\
	../dmtree/tr181/times.c						\
	../dmtree/tr181/upnp.c						\
	../dmtree/tr181/wifi.c						\
	../dmtree/tr181/ethernet.c					\
	../dmtree/tr181/atm.c						\
	../dmtree/tr181/ptm.c						\
	../dmtree/tr181/bridging.c					\
	../dmtree/tr181/hosts.c						\
	../dmtree/tr181/dhcpv4.c					\
	../dmtree/tr181/ip.c						\
	../dmtree/tr181/ppp.c						\
	../dmtree/tr181/nat.c						\
	../dmtree/tr181/routing.c					\
	../dmtree/tr181/firewall.c					\
	../dmtree/tr181/dns.c						\
	../dmtree/tr181/users.c						\
	../dmtree/tr181/dhcpv6.c					\
	../dmtree/tr181/dsl.c						\
	../dmtree/tr181/fast.c						\
	../dmtree/tr181/interfacestack.c			\
	../dmtree/tr181/usb.c 						\
	../dmtree/tr181/datamodelversion.c			\
	../dmtree/tr181/gre.c 						\
	../dmtree/tr181/dynamicdns.c				\
	../dmtree/tr181/security.c					\
	../dmtree/tr181/lanconfigsecurity.c			\
	../dmtree/tr181/ieee1905.c					\
	../dmtree/tr181/qos.c 						\
	../dmtree/tr181/softwaremodules.c			\
	../dmtree/tr181/routeradvertisement.c
endif #BBF_TR181

if BBF_TR104
libbbfdm_la_SOURCES +=	\
	../dmtree/tr104/common.c				\
	../dmtree/tr104/servicesvoiceservicecalllog.c		\
	../dmtree/tr104/servicesvoiceservicesip.c		\
	../dmtree/tr104/servicesvoiceservice.c			\
	../dmtree/tr104/servicesvoiceservicecapabilities.c	\
	../dmtree/tr104/servicesvoiceservicepots.c		\
	../dmtree/tr104/servicesvoiceservicevoipprofile.c	\
	../dmtree/tr104/servicesvoiceservicecallcontrol.c	\
	../dmtree/tr104/servicesvoiceservicecodecprofile.c	\
	../dmtree/tr104/servicesvoiceservicereservedports.c
endif #BBF_TR104

if BBF_TR143
libbbfdm_la_SOURCES +=							\
	../dmtree/tr143/diagnostics.c
endif #BBF_TR143

if BBF_VENDOR_EXTENSION

libbbfdm_la_SOURCES +=	\
	../dmdynamicvendor.c 	\
	../dmtree/vendor/vendor.c

if BBF_VENDOR_IOPSYS

if BBF_TR181
libbbfdm_la_SOURCES +=	\
	../dmtree/vendor/iopsys/tr181/vendor.c					\
	../dmtree/vendor/iopsys/tr181/device.c					\
	../dmtree/vendor/iopsys/tr181/deviceinfo.c				\
	../dmtree/vendor/iopsys/tr181/bridging.c					\
	../dmtree/vendor/iopsys/tr181/ethernet.c					\
	../dmtree/vendor/iopsys/tr181/times.c						\
	../dmtree/vendor/iopsys/tr181/x_iopsys_eu_igmp.c 			\
	../dmtree/vendor/iopsys/tr181/x_iopsys_eu_mld.c
endif #BBF_TR181

if BBF_TR104
libbbfdm_la_SOURCES +=	\
	../dmtree/vendor/iopsys/tr104/servicesvoiceservicecalllog.c
endif #BBF_TR104

endif #BBF_VENDOR_IOPSYS

if BBF_VENDOR_OPENWRT

if BBF_TR181
libbbfdm_la_SOURCES +=	\
	../dmtree/vendor/openwrt/tr181/vendor.c					\
	../dmtree/vendor/openwrt/tr181/deviceinfo.c				\
	../dmtree/vendor/openwrt/tr181/qos.c
endif #BBF_TR181

endif #BBF_VENDOR_OPENWRT

if BBF_VENDOR_TEST

if BBF_TR181
libbbfdm_la_SOURCES +=	\
	../dmtree/vendor/test/tr181/vendor.c					\
	../dmtree/vendor/test/tr181/deviceinfo.c 				\
	../dmtree/vendor/test/tr181/firewall.c					\
	../dmtree/vendor/test/tr181/device.c 					\
	../dmtree/vendor/test/tr181/x_test_com_dropbear.c
endif #BBF_TR181

endif #BBF_VENDOR_TEST

endif #BBF_VENDOR_EXTENSION

libbbfdm_la_CFLAGS =		\
	$(AM_CFLAGS)			\
	$(LIBUCI_CFLAGS)		\
	$(LIBUBOX_CFLAGS)		\
	$(LIBUBUS_CFLAGS) 		\
	-Wall

libbbfdm_la_LDFLAGS = 		\
	$(AM_LDFLAGS)			\
	$(LIBUCI_LDFLAGS)		\
	$(LIBUBOX_LDFLAGS)		\
	$(LIBUBUS_LDFLAGS)		\
	$(LIBOPENSSL_LIBS)		\
	$(LIBMBETLS_LIBS)			

libbbfdm_la_LIBADD =		\
	$(AM_LIBS)				\
	$(LIBUCI_LIBS)			\
	$(LIBUBOX_LIBS)			\
	$(LIBUBUS_LIBS)			\
	$(LIBJSON_LIBS)			\
	$(LIBTRACE_LIBS)		\
	$(LBLOBMSG_LIBS) 		\
	$(LIBDLOPEN_LIBS) 		\
	$(LIBCURL_LIBS)			\
	$(LIBOPENSSL_LIBS)		\
	$(LIBCRYPTO_LIBS)		\
	-lbbf_api

libbbfdm_la_CFLAGS+=-I../
libbbfdm_la_CFLAGS+=-I../dmtree
libbbfdm_la_CFLAGS+=-I../dmtree/tr181
libbbfdm_la_CFLAGS+=-I../dmtree/tr104
libbbfdm_la_CFLAGS+=-I../dmtree/tr143
