#!/bin/sh

# Custom script to handle 'config.change' event broadcasted from procd
#
# Copyright © 2024 IOPSYS Software Solutions AB
# Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
#

# Send 'bbf.config.notify' event to notify about the 'config.change' from external configs
. /usr/share/libubox/jshn.sh

config="${1}"

if [ -z "${config}" ]; then
	exit 0
fi

json_init
json_add_string "config" "${config}"
json_compact

json_data=$(json_dump)

ubus send bbf.config.notify "${json_data}"

json_cleanup

exit 0
