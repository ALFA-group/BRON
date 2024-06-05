import json
import sys
import argparse
import os
from typing import List, Any
import arango
import logging
from collections import defaultdict

import pandas as pd
from tqdm import tqdm

from utils.mitigation_utils import (
    check_duplicates,
    update_BRON_graph_db,
    query_bron,
    get_mitigation_collection_names_wrapper,
    get_collection_names,
    clean_BRON_collections,
)
from graph_db.bron_arango import create_edge_document, get_schema, get_schemas, validate_entry


SG_OUT_DATA_DIR = "data/attacks"
SOFTWARE_BASENAME = "software"
SOFTWARE_EDGE_COLLECTION_NAMES = {"SoftwareTechnique": ("software", "technique")}
SOFTWARE_SG_OUT_DATA_DIR = os.path.join(SG_OUT_DATA_DIR, SOFTWARE_BASENAME)
SOFTWARE_BRON_DATA = defaultdict(list)
GROUP_BASENAME = "group"
GROUP_EDGE_COLLECTION_NAMES = {
    "GroupTechnique": ("group", "technique"),
    "GroupSoftware": ("group", "software"),
}
GROUP_SG_OUT_DATA_DIR = os.path.join(SG_OUT_DATA_DIR, GROUP_BASENAME)
GROUP_BRON_DATA = defaultdict(list)


def build_software(
    save_path: str,
    username: str,
    password: str,
    ip: str,
    validation: bool = True,
    update_bron_graphdb: bool = True,
):
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    assert client is not None
    _build_software(save_path, username, password, ip, client, validation)
    client.close()
    if update_bron_graphdb:
        update_BRON_graph_db(
            username,
            password,
            ip,
            SOFTWARE_BRON_DATA,
            SOFTWARE_EDGE_COLLECTION_NAMES,
            SOFTWARE_SG_OUT_DATA_DIR,
        )


def _build_software(
    save_path: str,
    username: str,
    password: str,
    ip: str,
    client,
    validation: bool = True,
):
    logging.info(
        f"Begin build software in BRON for {username} on {ip} with validation:{validation} with data from {save_path}"
    )
    
    file_path = os.path.join(save_path, f"software.jsonl")
    df = pd.read_json(file_path, lines=True)
    check_duplicates(df, ["name", "id"])

    df = df.sort_values(by=["original_id"])
    datatype = "software"
    if validation:
        schemas = get_schemas()
    cnt = 0
    for row in tqdm(df.iterrows()):
        value = row[1]
        _id = str(value["original_id"])
        entry = {
            "_key": _id,
            "original_id": _id,
            "name": value["name"],
            "datatype": datatype,
            "metadata": {"description": value["description"], "type": value["type"]},
        }
        if validation:
            schema = schemas[datatype]
            validate_entry(entry, schema)

        SOFTWARE_BRON_DATA[datatype].append(entry)
        cnt += 1

    file_path = os.path.join(save_path, f"software_technique_mapping.jsonl")
    df = pd.read_json(file_path, lines=True)
    edge_name = "SoftwareTechnique"
    if validation:
        schema = get_schema(edge_name)

    db = client.db("BRON", username=username, password=password, auth_method="basic", verify=True)
    collection_ = db.collection("technique")
    logging.info(f"Linking {len(df)} rows for {collection_.name}")
    for i in tqdm(range(len(df))):
        value = df.loc[i]
        result = query_bron(collection_, {"original_id": str(value["technique_id"])})

        if result is None:
            continue

        _from = f'{datatype}/{value["software_id"]}'
        _to = result["_id"]
        document = create_edge_document(_from, _to, schema, validation)
        SOFTWARE_BRON_DATA[edge_name].append(document)

    for key, value in SOFTWARE_BRON_DATA.items():
        file_path = os.path.join(SOFTWARE_SG_OUT_DATA_DIR, f"import_{key}.jsonl")
        with open(file_path, "w") as fd:
            for line in value:
                json.dump(line, fd)
                fd.write("\n")

        assert os.path.exists(file_path)
        logging.info(f"Wrote {key} to {file_path}")

    logging.info(f"End build software")


def build_groups(
    save_path: str,
    username: str,
    password: str,
    ip: str,
    validation: bool = True,
    update_bron_graphdb: bool = True,
):
    logging.info(f"Begin build groups in BRON for {username} on {ip} with validation:{validation}")
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    assert client is not None
    _build_groups(save_path, username, password, ip, client, validation)
    client.close()
    if update_bron_graphdb:
        update_BRON_graph_db(
            username,
            password,
            ip,
            GROUP_BRON_DATA,
            GROUP_EDGE_COLLECTION_NAMES,
            GROUP_SG_OUT_DATA_DIR,
        )
    logging.info(f"End build groups")


def _build_groups(
    save_path: str,
    username: str,
    password: str,
    ip: str,
    client,
    validation: bool = True,
):
    logging.info(f"Begin build groups in BRON for {username} on {ip} with validation:{validation}")
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    db = client.db("BRON", username=username, password=password, auth_method="basic")
    collection_name = "technique"
    software_bron = db.collection("software")
    file_path = os.path.join(save_path, f"group.jsonl")
    df = pd.read_json(file_path, lines=True)
    check_duplicates(df, ["name", "id"])

    df = df.sort_values(by=["original_id"])
    datatype = "group"
    if validation:
        schemas = get_schemas()
    cnt = 0
    for row in tqdm(df.iterrows()):
        value = row[1]
        _id = str(value["original_id"])
        entry = {
            "_key": _id,
            "original_id": _id,
            "name": value["name"],
            "datatype": datatype,
            "metadata": {
                "description": value["description"],
                "aliases": value["aliases"],
            },
        }
        if validation:
            schema = schemas[datatype]
            validate_entry(entry, schema)

        GROUP_BRON_DATA[datatype].append(entry)
        cnt += 1

    file_path = os.path.join(save_path, f"group_technique_mapping.jsonl")
    df = pd.read_json(file_path, lines=True)
    edge_name = "GroupTechnique"
    technique_collection = db.collection("technique")
    if validation:
        schema = get_schema(edge_name)

    for row in tqdm(df.iterrows()):
        value = row[1]
        result = query_bron(technique_collection, {"original_id": str(value["technique_id"])})
        if result is None:
            continue

        _from = f'{datatype}/{value["group_id"]}'
        _to = result["_id"]
        document = create_edge_document(_from, _to, schema, validation)
        GROUP_BRON_DATA[edge_name].append(document)

    file_path = os.path.join(save_path, f"group_software_mapping.jsonl")
    df = pd.read_json(file_path, lines=True)
    edge_name = "GroupSoftware"
    software_collection = db.collection("software")
    if validation:
        schema = get_schema(edge_name)

    for row in tqdm(df.iterrows()):
        value = row[1]
        result = query_bron(software_collection, {"original_id": str(value["software_id"])})
        if result is None:
            continue

        _from = f'{datatype}/{value["group_id"]}'
        _to = result["_id"]
        document = create_edge_document(_from, _to, schema, validation)
        GROUP_BRON_DATA[edge_name].append(document)

    for key, value in GROUP_BRON_DATA.items():
        file_path = os.path.join(GROUP_SG_OUT_DATA_DIR, f"import_{key}.jsonl")
        with open(file_path, "w") as fd:
            for line in value:
                json.dump(line, fd)
                fd.write("\n")

        assert os.path.exists(file_path)
        logging.info(f"Wrote {key} to {file_path}")

    logging.info(f"End build groups")


def build_software_and_groups(
    save_path: str, username: str, password: str, ip: str, validation: bool = True
):
    logging.info(
        f"Begin build software and groups in BRON for {username} on {ip} with validation:{validation}"
    )
    os.makedirs(SOFTWARE_SG_OUT_DATA_DIR, exist_ok=True)
    os.makedirs(GROUP_SG_OUT_DATA_DIR, exist_ok=True)
    build_software(save_path, username, password, ip, validation)
    build_groups(save_path, username, password, ip, validation)
    logging.info(f"End build software and groups")


def parse_args(args: List[str]) -> Any:
    parser = argparse.ArgumentParser(description="Link ENGAGE mitigations to BRON")
    parser.add_argument("--username", type=str, required=True, help="DB username")
    parser.add_argument("--password", type=str, required=True, help="DB password")
    parser.add_argument("--ip", type=str, required=True, help="DB IP address")
    parser.add_argument("--data_folder", type=str, required=True, help="Data folder")
    parser.add_argument("--clean_db", action="store_true", help="Remove collections")
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
    if args_.clean_db:
        collections = {SOFTWARE_BASENAME, GROUP_BASENAME}
        collections.update(SOFTWARE_EDGE_COLLECTION_NAMES.keys())
        collections.update(GROUP_EDGE_COLLECTION_NAMES.keys())
        logging.info(f"Clean {collections}")
        clean_BRON_collections(args_.username, args_.password, args_.ip, collections)
        sys.exit(0)

    build_software_and_groups(
        args_.data_folder,
        args_.username,
        args_.password,
        args_.ip,
    )
