#!/bin/sh

# Custom script to handle 'config.change' event broadcasted from procd
#
# Copyright © 2024 IOPSYS Software Solutions AB
# Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
#

# Send 'bbf.config.notify' event to notify about the 'config.change' from external configs
ubus send bbf.config.notify

exit 0
