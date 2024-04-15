#!/bin/bash

echo "# Setting pipeline ci credentials"

if [ -n "${CI_SERVER_HOST}" ]; then
	echo "https://gitlab-ci-token:${CI_JOB_TOKEN}@${CI_SERVER_HOST}" > ~/.git-credential
	git config --global credential.helper "store --file ~/.git-credential"
fi

