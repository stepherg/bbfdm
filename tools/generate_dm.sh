#!/bin/bash

# Set variables
CONTAINER_NAME="generate_dm_tools"
IMAGE_NAME="dev.iopsys.eu:5050/iopsys/gitlab-ci-pipeline/code-analysis:latest"
INPUT=""
root="${PWD/tools}"

usages()
{
	echo "Usage: $0 [OPTIONS]..."
	echo
	echo "    -I <docker image>"
	echo "    -i json input file path relative to top directory"
	echo "    -h help"
	echo
	echo
	echo "examples:"
	echo "~/git/bbfdm$ ./tools/generate_dm.sh -i tools/tools_input.json"
	echo
}

runner()
{
	# Create and start the Docker container
	docker run --rm -it -v"${root}:/bbfdm" -w "/bbfdm" \
		--entrypoint=/bin/bash --name "$CONTAINER_NAME" "$IMAGE_NAME" \
		-c "./gitlab-ci/generate_supported_dm.sh /bbfdm/${1}"
}

while getopts n:I:i:h opts
do
	case "${opts}" in
		n) CONTAINER_NAME="${OPTARG}";;
		I) IMAGE_NAME="${OPTARG}";;
		i) INPUT="${OPTARG}";;
		h) usages; exit 0;;
		*) usages; exit 0;;
	esac
done

runner ${INPUT}
