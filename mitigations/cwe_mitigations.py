import logging
from typing import List, Any
import argparse
import os
import sys
import json

import arango
import pandas as pd
import utils
from graph_db.bron_arango import get_schemas, validate_entry

from utils.mitigation_utils import (
    clean_BRON_mitigation,
    get_collection_names,
    get_mitigation_collection_names_wrapper,
    query_bron,
    check_duplicates,
    update_BRON_graph_db,
)


CWE_OUT_DATA_DIR = "data/mitigations/cwe"
CWE_MITIGATION_BASENAME = "cwe"
CWE_MITIGATION_COLLECTION_NAMES = get_collection_names(CWE_MITIGATION_BASENAME)
CWE_MITIGATION_NAME_LOOKUP = {}
CWE_MITIGATION_BRON_DATA = {}
get_mitigation_collection_names_wrapper(
    CWE_MITIGATION_COLLECTION_NAMES,
    CWE_MITIGATION_NAME_LOOKUP,
    CWE_MITIGATION_BRON_DATA,
    CWE_MITIGATION_BASENAME,
)


def _make_bron_data(
    cwe_file_path: str, username: str, password: str, ip: str, validation: bool = True
):
    logging.info(f"Begin CWE mitgations for BRON for {ip} from {cwe_file_path}")
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    db = client.db("BRON", username=username, password=password, auth_method="basic")
    cwe_bron = db.collection("cwe")
    with open(cwe_file_path, "r") as fd:
        df = pd.read_json(fd)

    if validation:
        schemas = get_schemas()

    check_duplicates(df, ["Name", "ID"])
    df = df.sort_values(by=["ID"])
    cnt = 0
    for row in df.iterrows():
        value = row[1]
        for mitigation in value["Potential Mitigations"]:
            datatype = "cwe_mitigation"
            _id = f"{datatype}_{cnt:05}"
            entry = {
                "_key": _id,
                "original_id": str(value["ID"]),
                "name": value["Name"],
                "metadata": mitigation,
                "datatype": datatype,
            }
            if validation:
                validate_entry(entry, schemas[datatype])

            CWE_MITIGATION_BRON_DATA[datatype].append(entry)
            cnt += 1
            edge_name = "CweCwe_mitigation"
            # TODO fixs this, should not happen...
            try:
                result = query_bron(cwe_bron, {"original_id": str(value["ID"])})
                assert (
                    result is not None
                ), f"There must be a CWE that connects to the CWE mitigation. {entry}"

                _to = f"{datatype}/{_id}"
                _from = result["_id"]
                entry = {
                    "_id": f"{edge_name}/{_from}-{_to}",
                    "_from": _from,
                    "_to": _to,
                }
                if validation:
                    validate_entry(entry, schemas[edge_name])

                CWE_MITIGATION_BRON_DATA[edge_name].append(entry)
            except AssertionError as e:
                logging.error(e)

        for mitigation in value["Detection Methods"]:
            datatype = "cwe_detection"
            _id = f"{datatype}_{cnt:05}"
            entry = {
                "_key": _id,
                "original_id": str(value["ID"]),
                "name": value["Name"],
                "metadata": mitigation,
                "datatype": datatype,
            }
            if validation:
                validate_entry(entry, schemas[datatype])

            CWE_MITIGATION_BRON_DATA[datatype].append(entry)
            cnt += 1

            edge_name = "CweCwe_detection"
            result = query_bron(cwe_bron, {"original_id": str(value["ID"])})
            assert (
                result is not None
            ), f"ERROR: There must be a CWE that connects to the CWE detection. {entry}"

            _to = f"{datatype}/{_id}"
            _from = result["_id"]
            entry = {"_id": f"{edge_name}/{_from}-{_to}", "_from": _from, "_to": _to}
            if validation:
                validate_entry(entry, schemas[edge_name])

            CWE_MITIGATION_BRON_DATA[edge_name].append(entry)

    client.close()
    for key, value in CWE_MITIGATION_BRON_DATA.items():
        file_path = os.path.join(CWE_OUT_DATA_DIR, f"import_{key}.jsonl")
        with open(file_path, "w") as fd:
            for line in value:
                json.dump(line, fd)
                fd.write("\n")

        assert os.path.exists(file_path)
        logging.info(f"Wrote {key} to {file_path}")


def update_BRON_graph_db(username: str, password: str, ip: str):
    utils.mitigation_utils.update_BRON_graph_db(
        username,
        password,
        ip,
        CWE_MITIGATION_BRON_DATA,
        CWE_MITIGATION_NAME_LOOKUP,
        CWE_OUT_DATA_DIR,
    )


def clean_BRON_cwe_mitigation(username: str, password: str, ip: str) -> None:
    clean_BRON_mitigation(username, password, ip, CWE_MITIGATION_BRON_DATA)


def main(cwe_file_path: str, username: str, password: str, ip: str, validation: bool = True):
    os.makedirs(CWE_OUT_DATA_DIR, exist_ok=True)
    _make_bron_data(cwe_file_path, username, password, ip, validation)


def parse_args(args: List[str]) -> Any:
    parser = argparse.ArgumentParser(description="Link ENGAGE mitigations to BRON")
    parser.add_argument("--username", type=str, required=True, help="DB username")
    parser.add_argument("--password", type=str, required=True, help="DB password")
    parser.add_argument("--ip", type=str, required=True, help="DB IP address")
    parser.add_argument(
        "--cwe_file_path",
        type=str,
        required=True,
        help="CWE file path, e.g. download_threat_information/cwe_from_xml.json",
    )
    parser.add_argument(
        "--arango_import",
        action="store_true",
        help="Create mitigation files and use arangoimport with created json files. Requires `arangoimport`.",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Delet Engage related collections Requires `arangoimport`.",
    )
    args_p = parser.parse_args(args)
    return args_p


if __name__ == "__main__":
    log_file = os.path.basename(__file__).replace(".py", ".log")
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s",
        level=logging.INFO,
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )

    args_ = parse_args(sys.argv[1:])
    if args_.clean:
        clean_BRON_cwe_mitigation(args_.username, args_.password, args_.ip)

    if args_.arango_import:
        update_BRON_graph_db(
            args_.username,
            args_.password,
            args_.ip,
        )
    else:
        main(args_.cwe_file_path, args_.username, args_.password, args_.ip)
