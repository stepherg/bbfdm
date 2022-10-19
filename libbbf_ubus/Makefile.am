MAINTAINERCLEANFILES = Makefile.in
ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libbbf_ubus.la

libbbf_ubus_la_SOURCES =	\
	../dmentry.c 		\
	../dmbbfcommon.c	\
	libbbf_ubus.c

libbbf_ubus_la_CFLAGS =		\
	$(AM_CFLAGS)			\
	$(LIBUCI_CFLAGS)		\
	$(LIBUBOX_CFLAGS)		\
	$(LIBUBUS_CFLAGS)

libbbf_ubus_la_LDFLAGS = 		\
	$(AM_LDFLAGS)			\
	$(LIBUCI_LDFLAGS)		\
	$(LIBUBOX_LDFLAGS)		\
	$(LIBUBUS_LDFLAGS)

libbbf_ubus_la_LIBADD =		\
	$(AM_LIBS)			\
	$(LIBUCI_LIBS)			\
	$(LIBUBOX_LIBS)			\
	$(LIBUBUS_LIBS)			\
	$(LIBJSON_LIBS)			\
	$(LBLOBMSG_LIBS) 		\
	$(LIBCURL_LIBS)			\
	-L../bin/

libbbf_ubus_la_CFLAGS+=-I../
libbbf_ubus_la_CFLAGS+=-I../include
