#!/bin/bash

echo "install dependencies of bbfdm"

source ./gitlab-ci/shared.sh

# install required packages
exec_cmd apt update
exec_cmd pip3 install xlwt

mkdir -p /etc/bbfdm/dmmap
# Create directories for micro-service configuration and shared files
[ ! -d "${BBFDM_MS_CONF}" ] && mkdir -p "${BBFDM_MS_CONF}"
[ ! -d "${BBFDM_MS_DIR}" ] && mkdir -p "${BBFDM_MS_DIR}"

# Clean up generated files
rm -rf "${BBFDM_MS_DIR:?}"/*
rm -f "${BBFDM_MS_CONF}"/*
rm -f "${BBFDM_DMMAP_DIR}"/*

install_libeasy
# compile and install Core Data Model as a micro-service
install_libbbf "${1}"

# Install datamodel plugins/micro-service only when pipeline trigger for bbfdm
if [ -z "${1}" ]; then
	echo "Skip installation of micro-services ...."
	exit 0
fi

if [ "$1" == "bbfdm" ]; then
	#compile and install libbbf_test dynamic extension library
	install_libbbf_test
fi

JSON_FILE=$BBFDM_TOOLS_INPUT_FILE
JSON_DESC_PATH="/tmp/desc_files"
plugin_count=$(jq '.plugins | length' "$JSON_FILE")

# Create desc_files directory
[ -d "${JSON_DESC_PATH}" ] && rm -f ${JSON_DESC_PATH}
mkdir -p ${JSON_DESC_PATH}

ret=0
for i in $(seq 0 $((plugin_count - 1))); do
	echo "==== Processing plugin [$i] ===="

	repo=$(jq -r ".plugins[$i].repo" "$JSON_FILE")
	version=$(jq -r ".plugins[$i].version // empty" "$JSON_FILE")
	if [ -z "${version}" ]; then
		version=${BRANCH:-devel}
	fi

	plugin_name=$(basename "$repo" .git)
	dest="$BBFDM_PLUGIN_DEST/$plugin_name"

	# Adjust repo URL based on ~/.netrc existence
	NETRC_PATH="$HOME/.netrc"
	if [ ! -f "$NETRC_PATH" ]; then
		repo=${repo/https:\/\/dev.iopsys.eu\//git@dev.iopsys.eu:}
	fi

	echo "Repo path: $repo"
	echo "Plugin name: $plugin_name"
	echo "Destination: $dest"
	echo "Version: $version"

	# Install dependencies
	if [ "$plugin_name" == "ethmngr" ]; then
		install_libethernet
		install_libqos
	fi

	if [ "$plugin_name" == "parental-control" ]; then
		install_cmph
	fi

	if [ -d "$dest" ]; then
		echo "Directory $dest already exists, checkout $version"
		(cd "$dest" && git checkout . && git checkout "$version")
	else
		echo "Cloning $repo into $dest, branch ${version} ..."
		exec_cmd git clone -b "$version" "$repo" "$dest"
	fi

	cd "$dest" || exit 5

	# Compilation
	compile="$(jq -r ".plugins[$i].compile[]" "$JSON_FILE" 2>/dev/null)"
	if [ -n "${compile}" ]; then
		echo "Starting compilation..."
		while read -r cmd; do
			echo "Executing: $cmd"
			if ! eval "$cmd" > debug.log 2>&1; then
				echo "❌ Compilation command [$cmd] failed"
				ret=1
				break
			fi
		done <<< ${compile}
		[ $ret -eq 1 ] && break
	fi

	# Post-install
	post_install="$(jq -r ".plugins[$i].post_install[]" "$JSON_FILE" 2>/dev/null)"
	if [ -n "${post_install}" ]; then
		echo "Running post-install steps..."
		while read -r post_cmd; do
			echo "Executing: $post_cmd"
			if ! eval "$post_cmd" > debug.log 2>&1; then
				ret=1
				echo "❌ Post-install command [$post_cmd] failed"
				break
			fi
		done <<< ${post_install}
		[ $ret -eq "1" ] && break
	fi

	# Save dm_info_file if defined
	dm_info_file=$(jq -r ".plugins[$i].dm_info_file // empty" "$JSON_FILE")
	if [ -n "$dm_info_file" ]; then
		src_file="$dest/$dm_info_file"
		out_file="/tmp/desc_files/${i}_${plugin_name}.json"
		if [ -f "$src_file" ]; then
			echo "Saving dm_info_file to $out_file"
			cp -f "$src_file" "$out_file"
		else
			echo "❌ dm_info_file not found: $src_file"
			ret=1
		fi
	fi

	cd .. || exit 7

	if [ ${ret} -eq 0 ]; then
		echo "✅ Plugin [$plugin_name] build complete."
	else
		echo "❌ Plugin [$plugin_name] build failed"
		break
	fi
done

exit $ret
