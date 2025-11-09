import logging
from typing import List, Any
import argparse
import os
import sys
import json

import arango
import pandas as pd
from tqdm import tqdm

from graph_db.bron_arango import create_edge_document, get_schema, get_schemas, validate_entry
from mitigations.capec_mitigations import clean_BRON_mitigation
import utils.mitigation_utils as mitigation_utils


TECHNIQUE_MITIGATION_OUT_DATA_DIR = "data/mitigations/technique"
TECHNIQUE_MITIGATION_BASENAME = "technique"
TECHNIQUE_MITIGATION_EDGE_COLLECTION_NAMES = (
    "technique_mitigation",
    "technique_detection_strategy",
    "technique_analytic",
    "technique_data_component",
    "TechniqueTechnique_mitigation",
    "TechniqueTechnique_detection_strategy",
    "Technique_analyticTechnique_detection_strategy",
    "Technique_data_componentTechnique_analytic",
)
TECHNIQUE_MITIGATION_EDGE_COLLECTION_NAMES = tuple(set(TECHNIQUE_MITIGATION_EDGE_COLLECTION_NAMES))

TECHNIQUE_MITIGATION_NAME_LOOKUP = {
    "TechniqueTechnique_mitigation": ("technique", "technique_mitigation"),
    "TechniqueTechnique_detection_strategy": ("technique", "technique_detection_strategy"),
    "Technique_analyticTechnique_detection_strategy": ("technique_analytic", "technique_detection_strategy"),
    "Technique_data_componentTechnique_analytic": ("technique_data_component", "technique_analytic"),
}
TECHNIQUE_MITIGATION_BRON_DATA = dict([(k, []) for k in TECHNIQUE_MITIGATION_EDGE_COLLECTION_NAMES])


def _make_bron_data(save_path: str, username: str, password: str, ip: str, validation: bool = True):
    logging.info(f"Begin technique mitgations for BRON for {ip} from {save_path}")
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    db = client.db("BRON", username=username, password=password, auth_method="basic")

    file_path = os.path.join(save_path, f"technique_mitigation.jsonl")
    assert os.path.exists(file_path), f"file {file_path} does not exist"
    df = pd.read_json(file_path, lines=True)
    mitigation_utils.check_duplicates(df, ["name", "id"])

    df = df.sort_values(by=["original_id"])
    datatype = "technique_mitigation"
    if validation:
        schemas = get_schemas()
    cnt = 0
    assert datatype in TECHNIQUE_MITIGATION_EDGE_COLLECTION_NAMES, f"datatype {datatype} not in {TECHNIQUE_MITIGATION_EDGE_COLLECTION_NAMES}"
    edge_name = "TechniqueTechnique_mitigation"
    assert edge_name in TECHNIQUE_MITIGATION_EDGE_COLLECTION_NAMES, f"edge_name {edge_name} not in {TECHNIQUE_MITIGATION_EDGE_COLLECTION_NAMES}"
    for row in tqdm(df.iterrows(), total=len(df), desc="Ingesting technique_mitigation nodes"):
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
    assert os.path.exists(file_path), f"file {file_path} does not exist"
    df = pd.read_json(file_path, lines=True)
    edge_name = "TechniqueTechnique_mitigation"
    if validation:
        schema = get_schema(edge_name)

    for row in tqdm(df.iterrows(), total=len(df), desc="Ingesting technique_mitigation_technique_mapping edges"):
        value = row[1]
        result = value["technique_id"]
        # TODO hack for techniques
        if not result.startswith("T"):
            continue

        _to = f'{datatype}/{value["technique_mitigation_id"]}'
        _from = f"technique/{result}"
        document = create_edge_document(_from, _to, schema, validation)
        TECHNIQUE_MITIGATION_BRON_DATA[edge_name].append(document)

    file_path = os.path.join(save_path, f"technique_detection_strategy.jsonl")
    assert os.path.exists(file_path), f"file {file_path} does not exist"
    df = pd.read_json(file_path, lines=True)
    mitigation_utils.check_duplicates(df, ["name", "id"])
    df = df.sort_values(by=["original_id"])
    file_path = os.path.join(save_path, f"technique_detection_strategy_technique_mapping.jsonl")
    df_map = pd.read_json(file_path, lines=True)
    cnt = 0
    for row in df.iterrows():
        value = row[1]
        datatype = "technique_detection_strategy"   
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

    edge_name = "TechniqueTechnique_detection_strategy"
    results = df_map[df_map["technique_detection_strategy_id"] == _id]["technique_id"]
    schema = schemas[edge_name]
    for result in results:
        _to = f"{datatype}/{_id}"
        _from = f"technique/{result}"
        document = create_edge_document(_from, _to, schema, validation)
        TECHNIQUE_MITIGATION_BRON_DATA[edge_name].append(document)

    
    # Ingest technique_detection_strategy_technique_mapping edges
    file_path = os.path.join(save_path, f"technique_detection_strategy_technique_mapping.jsonl")
    assert os.path.exists(file_path), f"file {file_path} does not exist"
    df = pd.read_json(file_path, lines=True)
    edge_name = "TechniqueTechnique_detection_strategy"
    if validation:
        schema = get_schema(edge_name)

    for row in tqdm(df.iterrows(), total=len(df), desc="Ingesting technique_detection_strategy_technique_mapping edges"):
        value = row[1]
        technique_id = value["technique_id"]
        if not technique_id.startswith("T"):
            continue

        _to = f'technique_detection_strategy/{value["technique_detection_strategy_id"]}'
        _from = f"technique/{technique_id}"
        document = create_edge_document(_from, _to, schema, validation)
        TECHNIQUE_MITIGATION_BRON_DATA[edge_name].append(document)

    # Ingest technique_analytic nodes
    file_path = os.path.join(save_path, f"technique_analytic.jsonl")
    assert os.path.exists(file_path), f"file {file_path} does not exist"
    df = pd.read_json(file_path, lines=True)
    mitigation_utils.check_duplicates(df, ["name", "id"])
    df = df.sort_values(by=["original_id"])
    datatype = "technique_analytic"
    if validation:
        schemas = get_schemas()
    cnt = 0
    assert datatype in TECHNIQUE_MITIGATION_BRON_DATA, f"datatype {datatype} not in {TECHNIQUE_MITIGATION_BRON_DATA}"
    edge_name = "Technique_analyticTechnique_detection_strategy"
    edge_schema = get_schema(edge_name)
    assert edge_name in TECHNIQUE_MITIGATION_EDGE_COLLECTION_NAMES, f"edge_name {edge_name} not in {TECHNIQUE_MITIGATION_EDGE_COLLECTION_NAMES}"
    for row in tqdm(df.iterrows(), total=len(df), desc="Ingesting technique_analytic nodes"):
        value = row[1]
        description = value.get("description", "")
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

    # Ingest technique_analytic_technique_detection_strategy_mapping edges
    file_path = os.path.join(save_path, f"technique_analytic_technique_detection_strategy_mapping.jsonl")
    assert os.path.exists(file_path), f"file {file_path} does not exist"
    df = pd.read_json(file_path, lines=True)
    
    for row in df.iterrows():
        value = row[1]
        _from = f'technique_analytic/{value["technique_analytic_id"]}'
        _to = f'technique_detection_strategy/{value["technique_detection_strategy_id"]}'
        document = create_edge_document(_from, _to, edge_schema, validation)
        TECHNIQUE_MITIGATION_BRON_DATA[edge_name].append(document)

    # Ingest technique_data_component nodes
    file_path = os.path.join(save_path, f"technique_data_component.jsonl")
    assert os.path.exists(file_path), f"file {file_path} does not exist"
    df = pd.read_json(file_path, lines=True)
    mitigation_utils.check_duplicates(df, ["name", "id"])
    df = df.sort_values(by=["original_id"])
    datatype = "technique_data_component"
    if validation:
        schemas = get_schemas()
    cnt = 0
    for row in tqdm(df.iterrows(), total=len(df), desc="Ingesting technique_data_component nodes"):
        value = row[1]
        description = value.get("description", "")
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

    # Ingest technique_data_component_technique_analytic_mapping edges
    file_path = os.path.join(save_path, f"technique_data_component_technique_analytic_mapping.jsonl")
    assert os.path.exists(file_path), f"file {file_path} does not exist"
    df = pd.read_json(file_path, lines=True)
    edge_name = "Technique_data_componentTechnique_analytic"
    if validation:
        schema = get_schema(edge_name)

    for row in df.iterrows():
        value = row[1]
        _from = f'technique_data_component/{value["technique_data_component_id"]}'
        _to = f'technique_analytic/{value["technique_analytic_id"]}'
        document = create_edge_document(_from, _to, schema, validation)
        TECHNIQUE_MITIGATION_BRON_DATA[edge_name].append(document)

    # Verify at least some edges were created
    edge_collections = [k for k in TECHNIQUE_MITIGATION_BRON_DATA.keys() if any(c.isupper() for c in k)]
    if edge_collections:
        assert any(len(TECHNIQUE_MITIGATION_BRON_DATA[k]) > 0 for k in edge_collections), "No edges were created"
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
