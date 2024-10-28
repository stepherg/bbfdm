#!/bin/bash

echo "install dependencies of bbfdm"

source ./gitlab-ci/shared.sh

# install required packages
exec_cmd apt update
exec_cmd apt install -y python3-pip iproute2 jq
exec_cmd pip3 install pexpect ubus xlwt ValgrindCI

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
fi
