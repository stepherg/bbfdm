#
# Copyright (C) 2019 IOPSYS
#

include $(TOPDIR)/rules.mk

PKG_NAME:=libbbfdm
PKG_VERSION:=1.0-2020-16-05
PKG_FIXUP:=autoreconf
PKG_SOURCE_URL:=https://dev.iopsys.eu/iopsys/bbf.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION=x
PKG_RELEASE=$(PKG_SOURCE_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_MAINTAINER:=IOPSYS Dev <dev@iopsys.eu>
CONFIG_SRC_TREE_OVERRIDE:=y

PKG_LICENSE:=LGPL-2.1
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

define Package/libbbfdm
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=Library for broadband-forum data model
  DEPENDS:=+libuci +libubox +libubus +libblobmsg-json +libjson-c +libtrace +libcurl
endef

define Package/libbbfdm/config
	source "$(SOURCE)/Config_bbfdm.in"
endef

define Package/libbbfdm/description
 Test description will update later.
endef

TARGET_CFLAGS += \
	-DBBF_VENDOR_LIST=\\\"$(CONFIG_BBF_VENDOR_LIST)\\\" \
	-DBBF_VENDOR_PREFIX=\\\"$(CONFIG_BBF_VENDOR_PREFIX)\\\" \
	-D_GNU_SOURCE -D_AADJ

ifeq ($(CONFIG_BBF_TR181),y)
CONFIGURE_ARGS += \
	--enable-tr181
endif

ifeq ($(CONFIG_BBF_TR104),y)
CONFIGURE_ARGS += \
	--enable-tr104
endif

ifeq ($(CONFIG_BBF_TR143),y)
CONFIGURE_ARGS += \
	--enable-tr143
endif

ifeq ($(CONFIG_BBF_VENDOR_EXTENSION),y)
CONFIGURE_ARGS += \
	--enable-vendor-extension

CONFIGURE_ARGS += \
	BBF_VENDOR_LIST="$(CONFIG_BBF_VENDOR_LIST)"

endif ##CONFIG_BBF_VENDOR_EXTENSION

ifeq ($(CONFIG_BBFDM_ENABLE_JSON_PLUGIN),y)
CONFIGURE_ARGS += \
	--enable-json-plugin
endif

ifeq ($(CONFIG_BBFDM_ENABLE_DOTSO_PLUGIN),y)
CONFIGURE_ARGS += \
	--enable-shared-library
endif

define Package/libbbfdm/install
	$(INSTALL_DIR) $(1)/lib
	$(CP) $(PKG_BUILD_DIR)/bin/.libs/libbbfdm.so* $(1)/lib/
	$(CP) $(PKG_BUILD_DIR)/bin/.libs/libbbf_api.so* $(1)/lib/
	$(INSTALL_DIR) $(1)/etc/bbfdm
	$(INSTALL_DIR) $(1)/etc/bbfdm/dmmap
	$(INSTALL_DIR) $(1)/usr/share/bbfdm
	$(CP) $(PKG_BUILD_DIR)/scripts/* $(1)/usr/share/bbfdm
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(INSTALL_DIR) $(1)/usr/include/libbbfdm $(1)/usr/include/libbbf_api
	$(CP) $(PKG_BUILD_DIR)/*.h $(1)/usr/include/libbbfdm/
	$(CP) $(PKG_BUILD_DIR)/libbbf_api/*.h $(1)/usr/include/libbbf_api/
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/bin/.libs/libbbfdm.{a,so*} $(1)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/bin/.libs/libbbf_api.{a,so*} $(1)/usr/lib/
endef

$(eval $(call BuildPackage,libbbfdm))
