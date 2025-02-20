#!/bin/bash

echo "install dependencies of bbfdm"

source ./gitlab-ci/shared.sh

# install required packages
exec_cmd apt update
exec_cmd pip3 install xlwt

# Create directories for micro-service configuration and shared files
[ ! -d "${BBFDM_MS_CONF}" ] && mkdir -p "${BBFDM_MS_CONF}"
[ ! -d "${BBFDM_MS_DIR}" ] && mkdir -p "${BBFDM_MS_DIR}"

# Make sure that all generated files are removed
rm -rf ${BBFDM_MS_DIR}/*
rm -f ${BBFDM_MS_CONF}/*
rm -f ${BBFDM_DMMAP_DIR}/*
rm -f ${BBFDM_LOG_FILE}

# compile and install Core Data Model as a micro-service
install_libbbf ${1}

#compile and install libbbf_test dynamic extension library
install_libbbf_test ${1}

# Install datamodel plugins/micro-service only when pipeline trigger for bbfdm
if [ -z "${1}" ]; then
	echo "Skip installation of micro-services ...."
else
	#install SYSMNGR Data Model as a micro-service
	echo "Installing System Manager (SYSMNGR) Data Model as a micro-service"
	install_sysmngr_as_micro_service

	#install WiFi Data Model as a micro-service
	echo "Installing WiFi Data Model (wifidmd) as a micro-service"
	install_wifidmd_as_micro_service

	#install Network Data Model as a micro-service
	echo "Installing Network Data Model (netmngr) as a micro-service"
	install_netmngr_as_micro_service

	#install Ethernet Data Model as a micro-service
	echo "Installing Ethernet Data Model (ethmngr) as a micro-service"
	install_ethmngr_as_micro_service
fi
