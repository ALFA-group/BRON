#!/bin/bash

# parse environment
ARANGO_ROOT_PASSWORD=$(cat $ARANGO_ROOT_PASSWORD_FILE)

# build BRON
python3 build.py ${DATA_DIR:+-o} ${DATA_DIR}

# create arango files to import
python3 bron_arango.py --username=root --password=${ARANGO_ROOT_PASSWORD} -f ${DATA_DIR:-/tmp}/full_data/full_output_data/BRON.json --ip=brondb

# import data into arrango
python3 bron_arango.py --arango_import --username=root --password=${ARANGO_ROOT_PASSWORD} --ip=brondb

