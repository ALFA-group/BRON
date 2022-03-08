#!/bin/bash

# parse environment
ARANGO_ROOT_PASSWORD=$(cat $ARANGO_ROOT_PASSWORD_FILE)

# build BRON
python3 tutorials/build_bron.py --username=root --password=${ARANGO_ROOT_PASSWORD} --ip=brondb