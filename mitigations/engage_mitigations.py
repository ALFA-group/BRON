import logging
from typing import Dict, List, Any
import argparse
import os
import sys
import json

import requests
import arango

from graph_db.bron_arango import get_edge_collection_name, get_schemas, validate_entry
import utils.mitigation_utils as mitigation_utils

ENGAGE_URL = "https://raw.githubusercontent.com/mitre/engage/main/Data/json/"
ENGAGE_OUT_DATA_DIR = "data/mitigations/engage"
ENGAGE_BRON_ID_MAP_NAME = "Engage_BRON_id_map"
BRON_ENGAGE_DATA = {
    "engage_goal": "goal_details.json",
    "engage_approach": "approach_details.json",
    "engage_activity": "activity_details.json",
    "engage_approach_activity_mappings": "approach_activity_mappings.json",
    "engage_goal_approach_mappings": "goal_approach_mappings.json",
    "engage_attack_mapping": "attack_mapping.json",
}
COLLECTION_NAMES = {
    "engage_goal": ("engage_goal",),
    "engage_approach": ("engage_approach",),
    "engage_activity": ("engage_activity",),
    "engage_approach_activity_mappings": ("engage_approach", "engage_activity"),
    "engage_goal_approach_mappings": ("engage_goal", "engage_approach"),
    "engage_attack_mapping": ("technique", "engage_activity"),
}


def _make_bron_data(
    data: Dict[str, Any], datatype: str, bron_id_map: Dict[str, str]
) -> Dict[str, Any]:
    keys = list(data.keys())
    keys.sort()
    bron_data = {}
    for cnt, key in enumerate(keys):
        value = data[key]
        _id = f"{datatype}_{cnt:05}"
        entry = {"original_id": key, "name": value["name"], "datatype": datatype}
        bron_data[_id] = entry
        bron_id_map[key] = _id

    return bron_data


def _make_bron_data_map(data: List[Dict[str, Any]]) -> Dict[str, Any]:
    bron_data = data
    return bron_data


def _make_bron_attack_groups_data_map(data: Dict[str, Any]) -> Dict[str, Any]:
    bron_data = []
    for _, values in data.items():
        for technique in values.get("techniques", []):
            technique_id = technique["technique_id"]
            if technique.get("sub_technique", ""):
                technique_id = f'{technique_id}.{technique.get("sub_technique")}'

            entry = {
                "groups_id": values["id"],
                "technique_id": technique_id,
            }
            bron_data.append(entry)

    return bron_data


def _make_bron_attack_data_map(data: List[Dict[str, Any]]) -> Dict[str, Any]:
    # TODO is it better to get the ATTACK map from "Activity Details"?
    bron_data = []
    for values in data:
        technique_id = values["attack_id"]
        entry = {"technique_id": technique_id, "activity_id": values["eac_id"]}
        bron_data.append(entry)

    return bron_data


def link_data():
    """Goal
    |_Approach
      |_Activity -> Technique
    """
    logging.info("Begin linking Engage data")
    # TODO hacky with one bron id map structure...
    bron_id_map = {}
    for datatype, file_name in BRON_ENGAGE_DATA.items():
        with open(os.path.join(ENGAGE_OUT_DATA_DIR, file_name), "r") as fd:
            data = json.load(fd)

        out_path = os.path.join(ENGAGE_OUT_DATA_DIR, f"bron_{datatype}.json")
        if "mapp" in datatype:
            # TODO what about BRON ids?
            if datatype in (
                "engage_approach_activity_mappings",
                "engage_goal_approach_mappings",
            ):
                bron_data = _make_bron_data_map(data)
            elif datatype == "engage_attack_groups_mapped":
                bron_data = _make_bron_attack_groups_data_map(data)
            elif datatype == "engage_attack_mapping":
                bron_data = _make_bron_attack_data_map(data)

        else:
            if datatype == "engage_attack_groups":
                dict_ = {}
                for e in data:
                    dict_[e["id"]] = e

                data = dict_

            bron_data = _make_bron_data(data, datatype, bron_id_map)

        with open(out_path, "w") as fd:
            json.dump(bron_data, fd, indent=1)

        assert os.path.exists(out_path)
        logging.info(f"Write Engage data {datatype} to {out_path}")

    out_path = os.path.join(ENGAGE_OUT_DATA_DIR, f"{ENGAGE_BRON_ID_MAP_NAME}.json")
    with open(out_path, "w") as fd:
        json.dump(bron_id_map, fd)

    assert os.path.exists(out_path)
    logging.info(f"Write Engage BRON id map to {out_path}")


def download_data():
    _download_engage()


def _download_engage():
    # TODO do not manually list the JSONS...
    # ENGAGE
    for data_file in BRON_ENGAGE_DATA.values():
        url = f"{ENGAGE_URL}{data_file}"
        logging.info(f"Download {url}")
        response = requests.get(url)
        file_path = os.path.join(ENGAGE_OUT_DATA_DIR, data_file)
        with open(file_path, "w") as fd:
            json.dump(response.json(), fd, indent=2)

        assert os.path.exists(file_path)
        logging.info(f"Stored: {file_path}")


def update_BRON_graph_db(username: str, password: str, ip: str, validation: bool = True) -> None:
    logging.info(f"Begin update graph db at {ip} with engage")
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    db = client.db("BRON", username=username, password=password, auth_method="basic")
    file_path = os.path.join(ENGAGE_OUT_DATA_DIR, f"{ENGAGE_BRON_ID_MAP_NAME}.json")
    with open(file_path, "r") as fd:
        bron_id_map = json.load(fd)

    if validation:
        schemas = get_schemas()

    technique_bron = db.collection("technique")
    for key, _ in BRON_ENGAGE_DATA.items():
        edge_collection = "mapp" in key
        collection_names = COLLECTION_NAMES[key]
        # TODO messy
        if edge_collection:
            collection_name = get_edge_collection_name(*collection_names)
        else:
            collection_name = collection_names[0]
        file_path = os.path.join(ENGAGE_OUT_DATA_DIR, f"bron_{key}.json")
        out_file_path = os.path.join(ENGAGE_OUT_DATA_DIR, f"import_bron_{key}.jsonl")
        empty_results = list()
        duplicates = list()
        with open(out_file_path, "w") as fd:
            with open(file_path, "r") as i_fd:
                data = json.load(i_fd)
                if not edge_collection:
                    for key_, value_ in data.items():
                        entry = {"_key": key_, "_id": f"{collection_name}/{key_}"}
                        entry.update(value_)
                        if validation:
                            schema = schemas[collection_name]
                            validate_entry(entry, schema)

                        json.dump(entry, fd)
                        fd.write("\n")
                else:
                    for el in data:
                        vals = list(el.items())
                        assert len(vals) == 2
                        if key in (
                            "engage_attack_mapping",
                            "engage_attack_groups_mapped",
                        ):
                            if key == "engage_attack_mapping":
                                idx = 0
                            else:
                                idx = 1
                            result = mitigation_utils.query_bron(
                                technique_bron, {"original_id": vals[idx][1]}
                            )
                            vals[idx] = ("technique_id", result["_id"])
                            if idx == 0:
                                _from = f"{vals[idx][1]}"
                                _to = f"{collection_names[1]}/{bron_id_map[vals[1][1]]}"
                            else:
                                _to = f"{vals[idx][1]}"
                                _from = f"{collection_names[0]}/{bron_id_map[vals[0][1]]}"

                        else:
                            _from = f"{collection_names[0]}/{bron_id_map[vals[0][1]]}"
                            _to = f"{collection_names[1]}/{bron_id_map[vals[1][1]]}"

                        entry = {
                            "_id": f"{collection_name}/{collection_names[0]}/{_from}-{collection_names[1]}/{_to}",
                            "_from": f"{_from}",
                            "_to": f"{_to}",
                        }
                        if validation:
                            schema = schemas[collection_name]
                            validate_entry(entry, schema)

                        json.dump(entry, fd)
                        fd.write("\n")

        assert os.path.exists(out_file_path)
        logging.info("Stored engage data {key} in {out_file_path}")
        logging.warning(f"engage data {key} has {len(empty_results)} empty results")
        logging.warning(f"engage data {key} has {len(duplicates)} duplicate results")
        mitigation_utils.import_into_arango(
            username, password, ip, fd.name, edge_collection, collection_name
        )
        if edge_collection:
            mitigation_utils.update_graph_in_graph_db(
                username, password, ip, edge_key=collection_names
            )
        else:
            mitigation_utils.update_graph_in_graph_db(
                username, password, ip, collection_name=collection_name
            )

    client.close()
    logging.info(f"Done update of graph db at {ip} with engage")


def clean_BRON_engage(username: str, password: str, ip: str) -> None:
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    db = client.db("BRON", username=username, password=password, auth_method="basic")
    for collection in db.collections():
        collection_name = collection["name"]
        if "engage" in collection_name or "Engage" in collection_name:
            db.delete_collection(collection_name)
            logging.info(f"DELETED {collection_name}")

    client.close()


def main(no_download: bool):
    os.makedirs(ENGAGE_OUT_DATA_DIR, exist_ok=True)
    # Download defend data https://ENGAGE.mitre.org/resources/
    if not no_download:
        download_data()
    link_data()


def parse_args(args: List[str]) -> Any:
    parser = argparse.ArgumentParser(description="Link ENGAGE mitigations to BRON")
    parser.add_argument("--username", type=str, required=True, help="DB username")
    parser.add_argument("--password", type=str, required=True, help="DB password")
    parser.add_argument("--ip", type=str, required=True, help="DB IP address")
    parser.add_argument("--no_download", action="store_true", help="Do not download data")
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
        clean_BRON_engage(args_.username, args_.password, args_.ip)

    if args_.arango_import:
        update_BRON_graph_db(args_.username, args_.password, args_.ip)
    else:
        main(args_.no_download)
