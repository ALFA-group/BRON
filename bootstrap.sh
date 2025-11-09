#!/bin/bash

# parse environment
ARANGO_ROOT_PASSWORD=$(cat $ARANGO_ROOT_PASSWORD_FILE)

# TODO build BRON a year at a time (Docker can run out of memory)
# build BRON

YEARS=(2024 2023 2022 2021 2020 2019 2018 2017 2016 2015 2014 2013 2012 2011 2010 2009 2008 2007 2006 2005 2004 2003 2002)
INITIAL_YEAR=2025
END_YEAR=$((INITIAL_YEAR + 1))
echo "++++ Building BRON for ${INITIAL_YEAR} to ${END_YEAR}"
python3 tutorials/build_bron.py --username=root --password=${ARANGO_ROOT_PASSWORD} --ip=brondb --start_year=${INITIAL_YEAR} --end_year=${END_YEAR} 

for YEAR in ${YEARS[@]}; do
    END_YEAR=$((YEAR + 1))
    echo "++++ Building BRON for ${YEAR} to ${END_YEAR}"
    python3 tutorials/build_bron.py --username=root --password=${ARANGO_ROOT_PASSWORD} --ip=brondb --start_year=${YEAR} --end_year=${END_YEAR} --no_atlas --no_mitigations
done

echo "++++ Building BRON for final mitigations"
END_YEAR=$((INITIAL_YEAR + 1))
python3 tutorials/build_bron.py --username=root --password=${ARANGO_ROOT_PASSWORD} --ip=brondb --no_arangodb --no_atlas --start_year=$INITIAL_YEAR --end_year=$END_YEAR
