#!/bin/sh

# Script to activate image in specified time.
#
# Copyright © 2022 IOPSYS Software Solutions AB
# Author: Amin Ben Ramdhane <amin.benramdhane@pivasoftware.com>
#

ROOT="$(dirname "${0}")"

CHECK_IDLE_FILE="${ROOT}/bbf_check_idle.sh"
RETRY_TIME=300
START_TIME=$(date +%s)
MODE="${1}"

log() {
    echo "${@}"|logger -t bbf.activate_firmware -p info
}

activate_and_reboot_device() {
	local bank_id="${1}"
	local success

	success=$(ubus call fwbank set_bootbank "{'bank':${bank_id}}" | jsonfilter -e @.success)
	if [ "${success}" != "true" ]; then
		log "Can't activate the bank id ${bank_id}"
		exit 1
	fi

	log "The device will restart after a few seconds"
	ubus call rpc-sys reboot
	exit 0
}

handle_whenidle_mode() {
	local bank_id="${1}"
	local end_time="${2}"
	local force_activation="${3}"
	local diff=0
	
	[ ! -x "${CHECK_IDLE_FILE}" ] && {
		activate_and_reboot_device "${bank_id}"
	}

	sh "${CHECK_IDLE_FILE}"
	if [ "$?" = "0" ]; then
		activate_and_reboot_device "${bank_id}"
	else
		[ "${end_time}" -gt "$((diff + RETRY_TIME))" ] && {
			sleep "${RETRY_TIME}"
		}

		diff=$(($(date +%s) - START_TIME))
	fi

	while [ "${end_time}" -gt "${diff}" ]; do
		sh "${CHECK_IDLE_FILE}"
		if [ "$?" = "0" ]; then
			activate_and_reboot_device "${bank_id}"
		else

			if [ "${end_time}" -gt "$((diff + RETRY_TIME))" ]; then
				sleep "${RETRY_TIME}"
			else
				break
			fi

			diff=$(($(date +%s) - START_TIME))
		fi

	done

	[ "${force_activation}" = "1" ] && {
		activate_and_reboot_device "${bank_id}"
	}
}

handle_confirmation_needed_mode() {

	log "[ConfirmationNeeded] mode is not implemented"
	exit 0
}

######################## main ########################
if [ "${MODE}" = "Immediately" ] || [ "${MODE}" = "AnyTime" ]; then
	activate_and_reboot_device "${2}"
elif [ "${MODE}" = "WhenIdle" ]; then
	handle_whenidle_mode "${2}" "${3}" "${4}"
elif [ "${MODE}" = "ConfirmationNeeded" ]; then
	handle_confirmation_needed_mode "${2}" "${3}" "${4}" "${5}" "${6}"
else
	log "[${MODE}] mode is not supported"
	exit 1
fi
