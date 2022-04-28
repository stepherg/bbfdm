AC_INIT([libbbfdm], [1.0], [dev@iopsys.eu])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign subdir-objects])

#AC_CONFIG_SUBDIRS([libbbf_ubus])

AC_ARG_ENABLE(tr181, [AS_HELP_STRING([--enable-tr181], [enable tr181 device feature])], AC_DEFINE(BBF_TR181),)
AM_CONDITIONAL([BBF_TR181],[test "x$enable_tr181" = "xyes"])

AC_ARG_ENABLE(tr104, [AS_HELP_STRING([--enable-tr104], [enable tr104 voice feature])], AC_DEFINE(BBF_TR104),)
AM_CONDITIONAL([BBF_TR104],[test "x$enable_tr104" = "xyes"])

AC_ARG_ENABLE(tr143, [AS_HELP_STRING([--enable-tr143], [enable tr143 diagnostics feature])], AC_DEFINE(BBF_TR143),)
AM_CONDITIONAL([BBF_TR143],[test "x$enable_tr143" = "xyes"])

AC_ARG_ENABLE(libopenssl, [AS_HELP_STRING([--enable-libopenssl], [enable libopenssl feature])], AC_DEFINE(LOPENSSL),)
AM_CONDITIONAL([LOPENSSL],[test "x$enable_libopenssl" = "xyes"])

AC_ARG_ENABLE(libwolfssl, [AS_HELP_STRING([--enable-libwolfssl], [enable libwolfssl feature])], AC_DEFINE(LWOLFSSL),)
AM_CONDITIONAL([LWOLFSSL],[test "x$enable_libwolfssl" = "xyes"])

AC_ARG_ENABLE(libmbedtls, [AS_HELP_STRING([--enable-libmbedtls], [enable libmbedtls feature])], AC_DEFINE(LMBEDTLS),)
AM_CONDITIONAL([LMBEDTLS],[test "x$enable_libmbedtls" = "xyes"])

AC_ARG_ENABLE(vendor_extension, [AS_HELP_STRING([--enable-vendor-extension], [enable vendor extension])], AC_DEFINE(BBF_VENDOR_EXTENSION),)
AM_CONDITIONAL([BBF_VENDOR_EXTENSION],[test "x$enable_vendor_extension" = "xyes"])

AC_ARG_ENABLE(json_plugin, [AS_HELP_STRING([--enable-json-plugin], [enable json plugin to extend datamodel])], AC_DEFINE(BBFDM_ENABLE_JSON_PLUGIN),)
AM_CONDITIONAL([BBFDM_ENABLE_JSON_PLUGIN],[test "x$enable_json_plugin" = "xyes"])

AC_ARG_ENABLE(shared_library, [AS_HELP_STRING([--enable-shared-library], [enable shared library support to extend datamodel])], AC_DEFINE(BBFDM_ENABLE_DOTSO_PLUGIN),)
AM_CONDITIONAL([BBFDM_ENABLE_DOTSO_PLUGIN],[test "x$enable_shared_library" = "xyes"])

AC_DEFINE_UNQUOTED(BBF_VENDOR_LIST, "$BBF_VENDOR_LIST")
AC_DEFINE_UNQUOTED(BBF_VENDOR_PREFIX, "$BBF_VENDOR_PREFIX")

case $BBF_VENDOR_LIST in
  *openwrt*) vendor_openwrt=yes ;;&
  *iopsys*) vendor_iopsys=yes ;;&
  *test*) vendor_test=yes ;;&
  *) ;;
esac

AM_CONDITIONAL([BBF_VENDOR_IOPSYS],[test "x$vendor_iopsys" = "xyes"])
AM_COND_IF([BBF_VENDOR_IOPSYS], [AC_DEFINE(BBF_VENDOR_IOPSYS)],)

AM_CONDITIONAL([BBF_VENDOR_OPENWRT],[test "x$vendor_openwrt" = "xyes"])
AM_COND_IF([BBF_VENDOR_OPENWRT], [AC_DEFINE(BBF_VENDOR_OPENWRT)],)

AM_CONDITIONAL([BBF_VENDOR_TEST],[test "x$vendor_test" = "xyes"])
AM_COND_IF([BBF_VENDOR_TEST], [AC_DEFINE(BBF_VENDOR_TEST)],)

# checks for programs
AC_PROG_CC
AM_PROG_CC_C_O
LT_INIT
AC_ENABLE_SHARED

LIBJSON_LIBS='-ljson-c'
AC_SUBST([LIBJSON_LIBS])

AC_ARG_WITH([uci-include-path],
  [AS_HELP_STRING([--with-uci-include-path],
    [location of the uci library headers])],
  [LIBUCI_CFLAGS="-I$withval"])
AC_SUBST([LIBUCI_CFLAGS])

AC_ARG_WITH([uci-lib-path],
  [AS_HELP_STRING([--with-uci-lib-path], [location of the uci library])], [LIBUCI_LDFLAGS="-L$withval"])
AC_SUBST([LIBUCI_LDFLAGS])

LIBUCI_LIBS='-luci'
AC_SUBST([LIBUCI_LIBS])

LIBTRACE_LIBS='-ltrace'
AC_SUBST([LIBTRACE_LIBS])

AC_ARG_WITH([libubox-include-path],
  [AS_HELP_STRING([--with-libubox-include-path],
    [location of the libubox library headers])],
  [LIBUBOX_CFLAGS="-I$withval"])
AC_SUBST([LIBUBOX_CFLAGS])

AC_ARG_WITH([libubox-lib-path],
  [AS_HELP_STRING([--with-libubox-lib-path], [location of the libubox library])], [LIBUBOX_LDFLAGS="-L$withval"])
AC_SUBST([LIBUBOX_LDFLAGS])

LIBUBOX_LIBS='-lubox'
AC_SUBST([LIBUBOX_LIBS])

AC_ARG_WITH([libubus-include-path],
  [AS_HELP_STRING([--with-libubus-include-path],
    [location of the libubus library headers])],
  [LIBUBUS_CFLAGS="-I$withval"])
AC_SUBST([LIBUBUS_CFLAGS])

AC_ARG_WITH([libubus-lib-path],
  [AS_HELP_STRING([--with-libubus-lib-path], [location of the libubus library])], [LIBUBOX_LDFLAGS="-L$withval"])
AC_SUBST([LIBUBUS_LDFLAGS])

LIBUBUS_LIBS='-lubus'
AC_SUBST([LIBUBUS_LIBS])

LBLOBMSG_LIBS='-lblobmsg_json'
AC_SUBST([LBLOBMSG_LIBS])

LIBDLOPEN_LIBS='-ldl'
AC_SUBST([LIBDLOPEN_LIBS])

LIBCURL_LIBS='-lcurl'
AC_SUBST([LIBCURL_LIBS])

AM_COND_IF([LWOLFSSL], [
	LIBSSL_LIBS='-lwolfssl'
	AC_SUBST([LIBSSL_LIBS])
	LIBCRYPTO_LIBS='-lcrypto'
	AC_SUBST([LIBCRYPTO_LIBS])
])

AM_COND_IF([LOPENSSL], [
	LIBSSL_LIBS='-lssl'
	AC_SUBST([LIBSSL_LIBS])
	LIBCRYPTO_LIBS='-lcrypto'
	AC_SUBST([LIBCRYPTO_LIBS])
])

AM_COND_IF([LMBEDTLS], [
	LIBSSL_LIBS='-lmbedtls'
	AC_SUBST([LIBSSL_LIBS])
	LIBCRYPTO_LIBS='-lmbedcrypto'
	AC_SUBST([LIBCRYPTO_LIBS])
])

# checks for header files
AC_CHECK_HEADERS([stdlib.h string.h])

# checks for typedefs, structures, and compiler characteristics
AC_TYPE_UINT8_T

# Makefiles
AC_CONFIG_FILES([
Makefile
bin/Makefile
])

AC_OUTPUT
