import logging
from typing import List, Any
import argparse
import os
import sys
import json

import arango
import pandas as pd
from graph_db.bron_arango import get_schemas, validate_entry

from utils.mitigation_utils import (
    check_duplicates,
    clean_BRON_mitigation,
    get_collection_names,
    get_mitigation_collection_names_wrapper,
)
import utils.mitigation_utils as mitigation_utils
from mitigations.cwe_mitigations import query_bron


CAPEC_OUT_DATA_DIR = "data/mitigations/capec"
CAPEC_MITIGATION_BASENAME = "capec"
CAPEC_MITIGATION_COLLECTION_NAMES = get_collection_names(CAPEC_MITIGATION_BASENAME)
CAPEC_MITIGATION_NAME_LOOKUP = {}
CAPEC_MITIGATION_BRON_DATA = {}
get_mitigation_collection_names_wrapper(
    CAPEC_MITIGATION_COLLECTION_NAMES,
    CAPEC_MITIGATION_NAME_LOOKUP,
    CAPEC_MITIGATION_BRON_DATA,
    CAPEC_MITIGATION_BASENAME,
)


def _make_bron_data(
    capec_file_path: str, username: str, password: str, ip: str, validation: bool = True
):
    logging.info(f"Begin CAPEC mitgations for BRON for {ip} from {capec_file_path}")
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    db = client.db("BRON", username=username, password=password, auth_method="basic")
    capec_bron = db.collection("capec")
    if validation:
        schemas = get_schemas()

    with open(capec_file_path, "r") as fd:
        df = pd.read_json(fd)

    check_duplicates(df, ["Name", "ID"])

    df = df.sort_values(by=["ID"])
    cnt = 0
    for row in df.iterrows():
        value = row[1]
        for mitigation in value["Mitigations"]:
            datatype = "capec_mitigation"
            _id = f"{datatype}_{cnt:05}"
            entry = {
                "_key": _id,
                "original_id": str(value["ID"]),
                "name": value["Name"],
                "metadata": mitigation,
                "datatype": datatype,
            }
            if validation:
                schema = schemas[datatype]
                validate_entry(entry, schema)

            CAPEC_MITIGATION_BRON_DATA[datatype].append(entry)
            cnt += 1

            edge_name = "CapecCapec_mitigation"
            result = query_bron(capec_bron, {"original_id": str(value["ID"])})
            if result is None:
                continue

            _to = f"{datatype}/{_id}"
            _from = result["_id"]
            entry = {"_id": f"{edge_name}/{_from}-{_to}", "_from": _from, "_to": _to}
            if validation:
                schema = schemas[edge_name]
                validate_entry(entry, schema)

            CAPEC_MITIGATION_BRON_DATA[edge_name].append(entry)

        for mitigation in value["Indicators"]:
            datatype = "capec_detection"
            _id = f"{datatype}_{cnt:05}"
            entry = {
                "_key": _id,
                "original_id": str(value["ID"]),
                "name": value["Name"],
                "metadata": mitigation,
                "datatype": datatype,
            }
            if validation:
                schema = schemas[datatype]
                validate_entry(entry, schema)

            CAPEC_MITIGATION_BRON_DATA[datatype].append(entry)
            cnt += 1

            edge_name = "CapecCapec_detection"
            result = query_bron(capec_bron, {"original_id": str(value["ID"])})
            if result is None:
                continue

            _to = f"{datatype}/{_id}"
            _from = result["_id"]
            entry = {"_id": f"{edge_name}/{_from}-{_to}", "_from": _from, "_to": _to}
            if validation:
                schema = schemas[edge_name]
                validate_entry(entry, schema)

            CAPEC_MITIGATION_BRON_DATA[edge_name].append(entry)

    client.close()
    for key, value in CAPEC_MITIGATION_BRON_DATA.items():
        file_path = os.path.join(CAPEC_OUT_DATA_DIR, f"import_{key}.jsonl")
        with open(file_path, "w") as fd:
            for line in value:
                json.dump(line, fd)
                fd.write("\n")

        assert os.path.exists(file_path)
        logging.info(f"Wrote {key} to {file_path}")


def update_BRON_graph_db(username: str, password: str, ip: str) -> None:
    mitigation_utils.update_BRON_graph_db(
        username,
        password,
        ip,
        CAPEC_MITIGATION_BRON_DATA,
        CAPEC_MITIGATION_NAME_LOOKUP,
        CAPEC_OUT_DATA_DIR,
    )


def clean_BRON_capec_mitigation(username: str, password: str, ip: str) -> None:
    clean_BRON_mitigation(username, password, ip, CAPEC_MITIGATION_BRON_DATA)


def main(
    capec_file_path: str, username: str, password: str, ip: str, validation: bool = True
):
    os.makedirs(CAPEC_OUT_DATA_DIR, exist_ok=True)
    _make_bron_data(capec_file_path, username, password, ip, validation)


def parse_args(args: List[str]) -> Any:
    parser = argparse.ArgumentParser(description="Link ENGAGE mitigations to BRON")
    parser.add_argument("--username", type=str, required=True, help="DB username")
    parser.add_argument("--password", type=str, required=True, help="DB password")
    parser.add_argument("--ip", type=str, required=True, help="DB IP address")
    parser.add_argument(
        "--capec_file_path",
        type=str,
        required=True,
        help="CAPEC file path, e.g. download_threat_information/capec_from_xml.json",
    )
    parser.add_argument(
        "--arango_import",
        action="store_true",
        help="Create mitigation files and use arangoimport with created json files. Requires `arangoimport`.",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Delete Engage related collections Requires `arangoimport`.",
    )
    args = parser.parse_args(args)
    return args


if __name__ == "__main__":
    log_file = os.path.basename(__file__).replace(".py", ".log")
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s",
        level=logging.INFO,
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )

    args_ = parse_args(sys.argv[1:])
    if args_.clean:
        clean_BRON_capec_mitigation(args_.username, args_.password, args_.ip)

    if args_.arango_import:
        update_BRON_graph_db(args_.username, args_.password, args_.ip)
    else:
        main(args_.capec_file_path, args_.username, args_.password, args_.ip)
