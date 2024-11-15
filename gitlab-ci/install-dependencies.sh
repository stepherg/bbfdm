#!/bin/bash

echo "install dependencies of bbfdm"

source ./gitlab-ci/shared.sh

# install required packages
exec_cmd apt update
exec_cmd pip3 install xlwt

# Make sure that all plugins are removed
[ ! -d "${BBFDM_PLUGIN_DIR}" ] && mkdir -p "${BBFDM_PLUGIN_DIR}"
rm -f ${BBFDM_PLUGIN_DIR}/*
rm -f ${BBFDM_LOG_FILE}

# compile and install libbbf
install_libbbf ${1}

#compile and install libbbf_test dynamic extension library
install_libbbf_test ${1}

# Install datamodel plugins/micro-service only when pipeline trigger for bbfdm
if [ -z "${1}" ]; then
	# Generate plugin_input.json
	jq 'del(.output)' tools/tools_input.json > /tmp/plugin_input.json

	# Install datamodel plugins
	./tools/generate_dm.py /tmp/plugin_input.json
	check_ret $?

	ls -l /usr/share/bbfdm/plugins/
else
	# Create directories for micro-service configuration and shared files
	mkdir -p /etc/bbfdm/micro_services
	mkdir -p /usr/share/bbfdm/micro_services

	#install SYSMNGR Data Model as a micro-service
	echo "Installing System Manager (SYSMNGR) Data Model as a micro-service"
	install_sysmngr_as_micro_service

	#install WiFi Data Model as a micro-service
	echo "Installing WiFi Data Model (wifidmd) as a micro-service"
	install_wifidmd_as_micro_service

	#install Network Data Model as a micro-service
	echo "Installing Network Data Model (netmngr) as a micro-service"
	install_netmngr_as_micro_service
fi
