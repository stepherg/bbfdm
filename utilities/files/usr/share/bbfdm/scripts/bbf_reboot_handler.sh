#!/bin/sh

# Script to handle Reboots Object
#
# Copyright © 2024 IOPSYS Software Solutions AB
# Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
#

. /lib/functions.sh

RESET_REASON_PATH="/tmp/reset_reason"
MAX_RETRIES=3
RETRY_DELAY=1

log() {
	echo "$@" | logger -t bbf_reboot -p info
}

reset_option_counter() {
	local option_name=$1
	local option_value=$2
	uci_set "deviceinfo" "globals" "${option_name}" "${option_value}"
}

increment_option_counter() {
	local option_name=$1
	local option_value=$(uci_get "deviceinfo" "globals" "${option_name}" "0")
	local counter=$((option_value + 1))
	uci_set "deviceinfo" "globals" "${option_name}" "$counter"
}

get_boot_trigger() {
	local trigger
	trigger=$(grep "triggered" ${RESET_REASON_PATH} | cut -d ':' -f2 | xargs)
	echo "${trigger}"
}

get_boot_reason() {
	local reason
	reason=$(grep "reason" ${RESET_REASON_PATH} | cut -d ':' -f2 | xargs)
	echo "${reason}"
}

calculate_boot_time() {
	# Get current time and uptime in seconds
	local current_time uptime_seconds boot_time boot_time_formatted

	current_time=$(date +%s)
	uptime_seconds=$(awk '{print $1}' /proc/uptime | cut -d. -f1)

	# Calculate the boot time by subtracting the uptime from the current time
	boot_time=$((current_time - uptime_seconds))

	# Convert the boot time to a human-readable format
	boot_time_formatted=$(date -d "@$boot_time" +"%Y-%m-%dT%H:%M:%SZ")

	echo "${boot_time_formatted}"
}

boot_reason_message() {
	# Generate a human-readable message based on the boot reason and trigger
	local trigger reason

	trigger=$(get_boot_trigger)

	if [ -n "${trigger}" ]; then
		case "${trigger}" in
			"defaultreset")
				echo "FACTORY RESET"
				;;
			"upgrade")
				echo "FIRMWARE UPGRADE"
				;;
			*)
				echo "${trigger}"
				;;
		esac
	else
		reason=$(get_boot_reason)
		case "${reason}" in
			"POR_RESET")
				echo "POWER ON RESET"
				;;
			*)
				echo "${reason}"
				;;
		esac
	fi
}

create_reboot_section() {
	local trigger=$1
	local reboot_sec

	reboot_sec="reboot_$(date +%Y%m%d%H%M%S)"
	uci_add "deviceinfo" "reboot" "${reboot_sec}"
	uci_set "deviceinfo" "${reboot_sec}" "time_stamp" "$(calculate_boot_time)"

	if [ "${trigger}" = "upgrade" ]; then
		uci_set "deviceinfo" "${reboot_sec}" "firmware_updated" "1"
	else
		uci_set "deviceinfo" "${reboot_sec}" "firmware_updated" "0"
	fi

	if [ "${trigger}" = "defaultreset" ]; then
		uci_set "deviceinfo" "${reboot_sec}" "cause" "FactoryReset"
	else
		local last_reboot_cause
		last_reboot_cause=$(uci_get "deviceinfo" "globals" "last_reboot_cause" "LocalReboot")
		uci_set "deviceinfo" "${reboot_sec}" "cause" "${last_reboot_cause}"
		uci_set "deviceinfo" "globals" "last_reboot_cause" ""
	fi

	uci_set "deviceinfo" "${reboot_sec}" "reason" "$(boot_reason_message)"
}

handle_reboot_action() {
	local trigger reason max_reboot_entries retry_count reboot_sec_num

	retry_count=0

	# Retry fetching the reset reason file
	while [ ! -f "${RESET_REASON_PATH}" ] && [ $retry_count -lt $MAX_RETRIES ]; do
		log "Warning: '${RESET_REASON_PATH}' not found. Attempt $((retry_count + 1)) of ${MAX_RETRIES}"
		sleep $RETRY_DELAY
		retry_count=$((retry_count + 1))
	done

	if [ ! -f "${RESET_REASON_PATH}" ]; then
		log "Error: '${RESET_REASON_PATH}' is not generated after ${MAX_RETRIES} attempts!!!"
		return 1
	fi

	uci_load "deviceinfo"

	trigger=$(get_boot_trigger)
	reason=$(get_boot_reason)

	# Reset or increment boot counter based on trigger
	if [ "${trigger}" = "defaultreset" ]; then
		## Reset all counters ##
		reset_option_counter "boot_count" "1"
		reset_option_counter "curr_version_boot_count" "0"
		reset_option_counter "watchdog_boot_count" "0"
		reset_option_counter "cold_boot_count" "0"
		reset_option_counter "warm_boot_count" "0"
	else
		# Incrementing boot counter
		increment_option_counter "boot_count"
	fi

	# Reset or increment current version boot counter based on trigger
	if [ "${trigger}" = "upgrade" ]; then
		# Resetting current version boot counter
		reset_option_counter "curr_version_boot_count" "1"
	else
		# Incrementing current version boot counter
		increment_option_counter "curr_version_boot_count"
	fi

	# Increment watchdog boot counter if the reason indicates a watchdog reset
	if echo "${reason}" | grep -qi "watchdog"; then
		# Incrementing watchdog boot counter
		increment_option_counter "watchdog_boot_count"
	fi

	# Increment cold or warm boot counter based on the reason
	if [ "${reason}" = "POR_RESET" ]; then
		increment_option_counter "cold_boot_count"
	else
		increment_option_counter "warm_boot_count"
	fi

	# Get the max reboot entries
	max_reboot_entries=$(uci_get "deviceinfo" "globals" "max_reboot_entries" "3")

	if [ "${max_reboot_entries}" -eq 0 ]; then
		# Commit the UCI changes to persist the configuration
		uci_commit "deviceinfo"
		return 0
	fi

	if [ $max_reboot_entries -gt 0 ]; then
		# Calculate the number of reboot sections in the config
		reboot_sec_num=$(uci -q show deviceinfo | grep "=reboot" | wc -l)

		# Delete excess reboot sections if they exceed the max reboot entries
		if [ "${reboot_sec_num}" -ge "${max_reboot_entries}" ]; then
			local diff=$((reboot_sec_num - max_reboot_entries + 1))

			for i in $(seq 1 $diff); do
				uci_remove "deviceinfo" "@reboot[0]"
			done
		fi
	fi

	# Create a new reboot section with the current boot information
	create_reboot_section "${trigger}"

	# Commit the UCI changes to persist the configuration
	uci_commit "deviceinfo"
}

# Run the main function
handle_reboot_action
exit 0
