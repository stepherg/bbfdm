#!/bin/bash

echo "Generate xml and xls artifacts"

source ./gitlab-ci/shared.sh

# install required packages
exec_cmd apt update
exec_cmd apt install -y python3-pip libxml2-utils
exec_cmd pip3 install xlwt

if [ -n "${CI_SERVER_HOST}" ]; then
	echo "machine ${CI_SERVER_HOST}" >>~/.netrc
	echo "login gitlab-ci-token" >>~/.netrc
	echo "password ${CI_JOB_TOKEN}" >>~/.netrc
fi

# Make sure that all plugins are removed
[ ! -d "${BBFDM_PLUGIN_DIR}" ] && mkdir -p "${BBFDM_PLUGIN_DIR}"
rm -f ${BBFDM_PLUGIN_DIR}/*

[ ! -d "${BBFDM_MS_DIR}" ] && mkdir -p "${BBFDM_MS_DIR}"
rm -f ${BBFDM_MS_DIR}/*

if [ -z "${1}" ]; then
	./tools/generate_dm.py tools/tools_input.json
else
	if [ ! -f "${1}" ]; then
		echo "Invalid input file ${1}"
	else
		./tools/generate_dm.py "${1}"
	fi
fi

check_ret $?

echo "Check if the required tools are generated"
[ ! -f "out/datamodel.xls" ] && echo "Excel file doesn't exist" && exit 1
[ ! -f "out/datamodel_hdm.xml" ] && echo "XML file with HDM format doesn't exist" && exit 1
[ ! -f "out/datamodel_default.xml" ] && echo "XML file with BBF format doesn't exist" && exit 1

echo "Validate datamodel_default generated XML file"
xmllint --schema test/tools/cwmp-datamodel-*.xsd out/datamodel_default.xml --noout
check_ret $?

echo "Generation of xml and xls artifacts :: PASS"
