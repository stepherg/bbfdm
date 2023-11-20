#!/bin/bash

echo "Generate xml and xls artifacts"

source ./gitlab-ci/shared.sh

mkdir -p /etc/supervisor/conf.d/
cp ./gitlab-ci/core_service.conf /etc/supervisor/conf.d/

is_supervisor_running=0
pp="$(pidof python3)"
[ -n "${pp}" ] && {
	if ps -p ${pp}|grep -wq supervisord; then
		is_supervisor_running=1
	fi
}

if [ "${is_supervisor_running}" -eq "1" ] ; then
	# starting base services
	supervisorctl reread
	supervisorctl update
else
	/usr/bin/supervisord -c /etc/supervisor/supervisord.conf
fi

sleep 5
supervisorctl status all

# install required packages
exec_cmd apt update
exec_cmd apt install -y python3-pip libxml2-utils
exec_cmd pip3 install jsonschema xlwt ubus pylint

if [ -n "${CI_SERVER_HOST}" ]; then
	echo "machine ${CI_SERVER_HOST}" >>~/.netrc
	echo "login gitlab-ci-token" >>~/.netrc
	echo "password ${CI_JOB_TOKEN}" >>~/.netrc
fi

# Make sure that all plugins are removed
repo_dir="/etc/bbfdm/plugins"
[ ! -d "${repo_dir}" ] && mkdir -p "${repo_dir}"
rm -f ${repo_dir}/*

# Make sure that all micro-services are removed
rm -rf /etc/app*

if pidof bbfdmd >/dev/null; then
	kill -9 $(pidof bbfdmd)
fi

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
xmllint --schema test/tools/cwmp-datamodel-1-8.xsd out/datamodel_default.xml --noout
check_ret $?

echo "Generation of xml and xls artifacts :: PASS"
