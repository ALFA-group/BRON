import logging
from typing import List, Any
import argparse
import os
import sys
import json

import arango
import pandas as pd

from graph_db.bron_arango import create_edge_document, get_schema, get_schemas, validate_entry
from mitigations.capec_mitigations import clean_BRON_mitigation
import utils.mitigation_utils as mitigation_utils


TECHNIQUE_MITIGATION_OUT_DATA_DIR = "data/mitigations/technique"
TECHNIQUE_MITIGATION_BASENAME = "technique"
TECHNIQUE_MITIGATION_EDGE_COLLECTION_NAMES = mitigation_utils.get_collection_names(
    TECHNIQUE_MITIGATION_BASENAME
)
TECHNIQUE_MITIGATION_NAME_LOOKUP = {}
TECHNIQUE_MITIGATION_BRON_DATA = {}
mitigation_utils.get_mitigation_collection_names_wrapper(
    TECHNIQUE_MITIGATION_EDGE_COLLECTION_NAMES,
    TECHNIQUE_MITIGATION_NAME_LOOKUP,
    TECHNIQUE_MITIGATION_BRON_DATA,
    TECHNIQUE_MITIGATION_BASENAME,
)


def _make_bron_data(save_path: str, username: str, password: str, ip: str, validation: bool = True):
    logging.info(f"Begin technique mitgations for BRON for {ip}")
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    db = client.db("BRON", username=username, password=password, auth_method="basic")

    file_path = os.path.join(save_path, f"technique_mitigation.jsonl")
    df = pd.read_json(file_path, lines=True)
    mitigation_utils.check_duplicates(df, ["name", "id"])

    df = df.sort_values(by=["original_id"])
    datatype = "technique_mitigation"
    if validation:
        schemas = get_schemas()
    cnt = 0
    for row in df.iterrows():
        value = row[1]
        description = value["description"]
        entry = {
            "_key": str(value["original_id"]),
            "original_id": str(value["original_id"]),
            "name": value["name"],
            "datatype": datatype,
            "metadata": {"description": description}
        }
        if validation:
            schema = schemas[datatype]
            validate_entry(entry, schema)

        TECHNIQUE_MITIGATION_BRON_DATA[datatype].append(entry)
        cnt += 1

    file_path = os.path.join(save_path, f"technique_mitigation_technique_mapping.jsonl")
    df = pd.read_json(file_path, lines=True)
    edge_name = "TechniqueTechnique_mitigation"
    if validation:
        schema = get_schema(edge_name)

    for row in df.iterrows():
        value = row[1]
        result = value["technique_id"]
        # TODO hack for techniques
        if not result.startswith("T"):
            continue

        _to = f'{datatype}/{value["technique_mitigation_id"]}'
        _from = f"technique/{result}"
        document = create_edge_document(_from, _to, schema, validation)
        TECHNIQUE_MITIGATION_BRON_DATA[edge_name].append(document)

    file_path = os.path.join(save_path, f"technique_detection.jsonl")
    df = pd.read_json(file_path, lines=True)
    mitigation_utils.check_duplicates(df, ["name", "id"])
    df = df.sort_values(by=["original_id"])
    file_path = os.path.join(save_path, f"technique_technique_detection_component_mapping.jsonl")
    df_map = pd.read_json(file_path, lines=True)
    cnt = 0
    for row in df.iterrows():
        value = row[1]
        datatype = "technique_detection"   
        _id = str(value["original_id"])
        description = value["description"]
        entry = {
            "_key": _id,
            "original_id": _id,
            "name": value["name"],
            "datatype": datatype,
            "metadata": {"description": description}
        }
        if validation:
            schema = schemas[datatype]
            validate_entry(entry, schema)

        TECHNIQUE_MITIGATION_BRON_DATA[datatype].append(entry)
        cnt += 1

        edge_name = "TechniqueTechnique_detection"
        results = df_map[df_map["technique_data_source_id"] == _id]["technique_id"]
        schema = schemas[edge_name]
        for result in results:
            _to = f"{datatype}/{_id}"
            _from = f"technique/{result}"
            document = create_edge_document(_from, _to, schema, validation)
            TECHNIQUE_MITIGATION_BRON_DATA[edge_name].append(document)

    assert len(TECHNIQUE_MITIGATION_BRON_DATA[edge_name]) > 0
    client.close()
    for key, value in TECHNIQUE_MITIGATION_BRON_DATA.items():
        file_path = os.path.join(TECHNIQUE_MITIGATION_OUT_DATA_DIR, f"import_{key}.jsonl")
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
        TECHNIQUE_MITIGATION_BRON_DATA,
        TECHNIQUE_MITIGATION_NAME_LOOKUP,
        TECHNIQUE_MITIGATION_OUT_DATA_DIR,
    )


def clean_BRON_technique_mitigation(username: str, password: str, ip: str) -> None:
    clean_BRON_mitigation(username, password, ip, TECHNIQUE_MITIGATION_BRON_DATA)


def main(save_path: str, username: str, password: str, ip: str, validation: bool = True):
    os.makedirs(TECHNIQUE_MITIGATION_OUT_DATA_DIR, exist_ok=True)
    _make_bron_data(save_path, username, password, ip, validation)


def parse_args(args: List[str]) -> Any:
    parser = argparse.ArgumentParser(description="Link ENGAGE mitigations to BRON")
    parser.add_argument("--username", type=str, required=True, help="DB username")
    parser.add_argument("--password", type=str, required=True, help="DB password")
    parser.add_argument("--ip", type=str, required=True, help="DB IP address")
    parser.add_argument(
        "--technique_file_folder",
        type=str,
        required=True,
        help="TECHNIQUE file folder, e.g. download_threat_information/",
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
        clean_BRON_technique_mitigation(args_.username, args_.password, args_.ip)

    if args_.arango_import:
        update_BRON_graph_db(args_.username, args_.password, args_.ip)
    else:
        main(args_.technique_file_folder, args_.username, args_.password, args_.ip)
