#!/usr/bin/env bash

# Copy README.md as index.md and change links
pip install -r requirements.txt

# Copy README.md as index.md and change links
sed -r -e 's![\.\/]*docs[\/]*!./!g' ../README.md  > index.md

# Start mkdocs local server
mkdocs serve -f mkdocs.yml
