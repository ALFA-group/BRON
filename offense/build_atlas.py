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
    clean_BRON_collections,
)
from graph_db.bron_arango import create_edge_document, get_edge_collection_name, get_schema, get_schemas, validate_entry


ATLAS_OUT_DATA_DIR = "data/attacks/atlas"
ATLAS_BASENAME = "atlas"
ATLAS_EDGE_COLLECTION_NAMES = {"Atlas_techniqueTechnique": ("atlas_technique", "technique"),
                               "Atlas_mitigationAtlas_technique": ("atlas_mitigation", "atlas_technique"),
                               "Atlas_mitigationTechnique_mitigation": ("atlas_mitigation", "technique_mitigation"),
                               "Atlas_tacticAtlas_technique": ("atlas_tactic", "atlas_technique"),
                               "Atlas_tacticTactic": ("atlas_tactic", "tactic"),
                               }
ATLAS_BRON_DATA = defaultdict(list)


def build_atlas(
    save_path: str,
    username: str,
    password: str,
    ip: str,
    validation: bool = True,
    update_bron_graphdb: bool = True,
):
    os.makedirs(ATLAS_OUT_DATA_DIR, exist_ok=True)
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    assert client is not None
    _build_atlas(save_path, username, password, ip, client, validation)    
    client.close()
    schemas = get_schemas().keys()
    # TODO Check names of collections are matching schema for everythint
    for edge_collection, values in ATLAS_EDGE_COLLECTION_NAMES.items():
        assert edge_collection in schemas, f"{edge_collection} not in {schemas}"
        assert all([v in schemas for v in values])
        assert get_edge_collection_name(*values) == edge_collection
        
    if update_bron_graphdb:
        update_BRON_graph_db(
            username,
            password,
            ip,
            ATLAS_BRON_DATA,
            ATLAS_EDGE_COLLECTION_NAMES,
            ATLAS_OUT_DATA_DIR,
        )


def _build_atlas(
    save_path: str,
    username: str,
    password: str,
    ip: str,
    client,
    validation: bool = True,
):
    logging.info(
        f"Begin build ATLAS in BRON for {username} on {ip} with validation:{validation} with data from {save_path}"
    )
    atlas_tactic_id_map = {}
    # Tactic
    file_path = os.path.join(save_path, f"atlas_tactics.jsonl")
    df = pd.read_json(file_path, lines=True)
    check_duplicates(df, ["name", "original_id"])

    df = df.sort_values(by=["original_id"])
    datatype = "atlas_tactic"
    if validation:
        schemas = get_schemas()
    cnt = 0
    for row in tqdm(df.iterrows()):
        value = row[1]
        _id = str(value["original_id"])
        entry = {
            "_key": _id,
            "original_id": str(value["original_id"]),
            "name": value["name"],
            "datatype": datatype,
            "metadata": {"description": value["description"]},
        }
        if validation:
            schema = schemas[datatype]
            validate_entry(entry, schema)

        atlas_tactic_id_map[entry["original_id"]] = _id
        ATLAS_BRON_DATA[datatype].append(entry)
        cnt += 1

    # TODO loop over edges and use link_data as in ecar_analytics
    file_path = os.path.join(save_path, f"atlas_tactic-attack_tactic_map.jsonl")
    df = pd.read_json(file_path, lines=True)
    edge_name = "Atlas_tacticTactic"
    if validation:
        schema = get_schema(edge_name)
        assert schema is not None, f"{schema} {edge_name}"
    db = client.db(
        "BRON", username=username, password=password, auth_method="basic", verify=True
    )
    collection_ = db.collection("tactic")
    logging.info(f"Linking {len(df)} rows for {collection_.name}")
    for i in tqdm(range(len(df))):
        value = df.loc[i]
        result = query_bron(collection_, {"original_id": str(value["tactic_id"])})
        if result is None:
            continue

        _from = f'{datatype}/{atlas_tactic_id_map[value["atlas_tactic_id"]]}'
        _to = result["_id"]
        document = create_edge_document(_from, _to, schema, validation)        
        ATLAS_BRON_DATA[edge_name].append(document)

    atlas_technique_id_map = {}
    # Technique
    file_path = os.path.join(save_path, f"atlas_techniques.jsonl")
    df = pd.read_json(file_path, lines=True)
    check_duplicates(df, ["name", "original_id"])

    df = df.sort_values(by=["original_id"])
    datatype = "atlas_technique"
    if validation:
        schemas = get_schemas()
    cnt = 0
    for row in tqdm(df.iterrows()):
        value = row[1]
        _id = str(value["original_id"])
        entry = {
            "_key": _id,
            "original_id": str(value["original_id"]),
            "name": value["name"],
            "datatype": datatype,
            "metadata": {"description": value["description"]},
        }
        if validation:
            schema = schemas[datatype]
            validate_entry(entry, schema)

        atlas_technique_id_map[entry["original_id"]] = _id
        ATLAS_BRON_DATA[datatype].append(entry)
        cnt += 1

    file_path = os.path.join(save_path, f"atlas_tactic-atlas_technique_map.jsonl")
    df = pd.read_json(file_path, lines=True)
    edge_name = "Atlas_tacticAtlas_technique"
    if validation:
        schema = get_schema(edge_name)

    # Not guaranteed to exist in the db
    collection_ = atlas_tactic_id_map
    logging.info(f"Linking {len(df)} rows for atlas tactic id map")
    for i in tqdm(range(len(df))):
        value = df.loc[i]
        result = collection_.get(value["atlas_tactic_id"], None)
        if result is None:
            continue

        _to = f'{datatype}/{atlas_technique_id_map[value["atlas_technique_id"]]}'
        _from = f'atlas_tactic/{result}'
        document = create_edge_document(_from, _to, schema, validation)                
        ATLAS_BRON_DATA[edge_name].append(document)

    file_path = os.path.join(save_path, f"atlas_technique-attack_technique_map.jsonl")
    df = pd.read_json(file_path, lines=True)
    edge_name = "Atlas_techniqueTechnique"
    if validation:
        schema = get_schema(edge_name)

    collection_ = db.collection("technique")
    logging.info(f"Linking {len(df)} rows for {collection_.name}")
    print(df.columns)
    for i in tqdm(range(len(df))):
        value = df.loc[i]
        result = query_bron(collection_, {"original_id": str(value["technique_id"])})
        if result is None:
            continue

        _from = f'{datatype}/{atlas_technique_id_map[value["atlas_technique_id"]]}'
        _to = result["_id"]
        document = create_edge_document(_from, _to, schema, validation)        
        ATLAS_BRON_DATA[edge_name].append(document)

    # Mitigations
    atlas_mitigation_id_map = {}
    file_path = os.path.join(save_path, f"atlas_mitigations.jsonl")
    df = pd.read_json(file_path, lines=True)
    check_duplicates(df, ["name", "original_id"])

    df = df.sort_values(by=["original_id"])
    datatype = "atlas_mitigation"
    if validation:
        schemas = get_schemas()
    cnt = 0
    for row in tqdm(df.iterrows()):
        value = row[1]
        _id = str(value["original_id"])
        entry = {
            "_key": _id,
            "original_id": str(value["original_id"]),
            "name": value["name"],
            "datatype": datatype,
            "metadata": {"description": value["description"], 'tags': value['tags']},
        }
        if validation:
            schema = schemas[datatype]
            validate_entry(entry, schema)

        atlas_mitigation_id_map[entry["original_id"]] = _id
        ATLAS_BRON_DATA[datatype].append(entry)
        cnt += 1

    file_path = os.path.join(save_path, f"atlas_mitigation-attack_mitigation_map.jsonl")
    df = pd.read_json(file_path, lines=True)
    edge_name = "Atlas_mitigationTechnique_mitigation"
    if validation:
        schema = get_schema(edge_name)

    assert schema is not None, f"{edge_name} gets no schema"
    collection_ = db.collection("technique_mitigation")
    logging.info(f"Linking {len(df)} rows for {collection_.name}")
    for i in tqdm(range(len(df))):
        value = df.loc[i]
        result = query_bron(collection_, {"original_id": str(value["technique_mitigation_id"])})
        if result is None:
            continue

        _from = f'{datatype}/{atlas_mitigation_id_map[value["atlas_mitigation_id"]]}'
        _to = result["_id"]
        print(_from, _to, schema)
        document = create_edge_document(_from, _to, schema, validation)        
        ATLAS_BRON_DATA[edge_name].append(document)
    
    file_path = os.path.join(save_path, f"atlas_mitigation-atlas_technique_map.jsonl")
    df = pd.read_json(file_path, lines=True)
    edge_name = "Atlas_mitigationAtlas_technique"
    if validation:
        schema = get_schema(edge_name)

    collection_ = atlas_technique_id_map
    logging.info(f"Linking {len(df)} rows for atlas technique ")
    for i in tqdm(range(len(df))):
        value = df.loc[i]
        result = collection_.get(value["atlas_technique_id"], None)
        if result is None:
            continue

        _from = f'{datatype}/{atlas_mitigation_id_map[value["atlas_mitigation_id"]]}'
        _to = f'atlas_technique/{result}'        
        document = create_edge_document(_from, _to, schema, validation)        
        ATLAS_BRON_DATA[edge_name].append(document)
    
    # Store BRON formatted data
    for key, value in ATLAS_BRON_DATA.items():
        file_path = os.path.join(ATLAS_OUT_DATA_DIR, f"import_{key}.jsonl")
        with open(file_path, "w") as fd:
            for line in value:
                json.dump(line, fd)
                fd.write("\n")

        assert os.path.exists(file_path)
        logging.info(f"Wrote {key} to {file_path}")

    logging.info(f"End build ATLAS")


def parse_args(args: List[str]) -> Any:
    parser = argparse.ArgumentParser(description="Link ATLAS mitigations to BRON")
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
        collections = {ATLAS_BASENAME,}
        collections.update(ATLAS_EDGE_COLLECTION_NAMES.keys())
        logging.info(f"Clean {collections}")
        clean_BRON_collections(args_.username, args_.password, args_.ip, collections)
        sys.exit(0)

    build_atlas(
        args_.data_folder,
        args_.username,
        args_.password,
        args_.ip,
    )
