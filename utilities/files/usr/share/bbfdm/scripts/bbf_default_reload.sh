#!/bin/sh

# Script: bbf_default_reload.sh
# Description:
#   This script reloads UCI Configs based on input args.
#   Input args should be space separated uci file names
#
# Usage:
#   sh bbf_default_reload.sh network firewall
#
# Actions:
#   - performs "ubus call uci commit '{"config":"<uci name>"}' for
#     each uci file received in argument list

. /usr/share/libubox/jshn.sh

log() {
	echo "${@}"|logger -t bbf.config.default.reload -p info
}

input="$@"

# Validate input
if [ -z "$input" ]; then
	log "Error: No input provided"
	exit 1
fi

for uci in ${input}; do
	log "Reloading ${uci} config"

	json_init
	json_add_string "config" "${uci}"
	json_compact

	json_data=$(json_dump)
	ubus -t 5 call uci commit "${json_data}"

	json_cleanup
done

exit 0
