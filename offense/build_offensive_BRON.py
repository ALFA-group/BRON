import argparse
import collections
import json
import gzip
import os
import sys
from typing import List, Dict, Any
import logging

import networkx as nx

from download_threat_information.parsing_scripts.parse_cve import (
    CVE_MAP_FILE,
    RECENT_CVE_MAP_FILE,
)

UNIQUE_ID = 0
BRON_PATH = "offense/original_id_to_bron_id"
# TODO refactor with a naming function might be cleaner
NAME_MAP_PATHS = {
    "tactic_map": "technique_tactic_map.json",
    "technique_names": "technique_name_map.json",
    "tactic_names": "tactic_id_name_map.json",
    "attack_map": "capec_technique_map.json",
    "capec_names": "capec_names.json",
    "capec_cwe": "capec_cwe_mapping.json",
    "cwe_names": "cwe_names.json",
    "cve_map": CVE_MAP_FILE,
    "cve_map_last_five_years": RECENT_CVE_MAP_FILE,
    "mitigations_name_map": "mitigations_name_map.json",
}
DESCRIPTION_MAP_PATHS = {
    "tactic_descriptions": "tactic_descriptions.json",
    "technique_descriptions": "technique_descriptions.json",
    "cwe_descriptions": "cwe_descriptions.json",
    "capec_descriptions": "capec_descriptions.json",
}
ID_DICT_PATHS = {
    "tactic": "tactic_name_to_bron_id.json",
    "technique": "technique_id_to_bron_id.json",
    "capec": "capec_id_to_bron_id.json",
    "cwe": "cwe_id_to_bron_id.json",
    "cve": "cve_id_bron_id.json",
    "cpe": "cpe_id_bron_id.json",
    "mitigation": "mitigation.json",
}


def build_graph(save_path: str, input_data_folder: str, recent_cves: bool = False):
    logging.info(f"Begin build BRON graph from {input_data_folder}")
    main_graph = nx.DiGraph()
    tactic_graph = add_tactic_technique_edges(main_graph, input_data_folder, save_path)
    attack_graph = add_capec_technique_edges(tactic_graph, input_data_folder, save_path)
    update_graph = add_capec_cwe_edges(attack_graph, input_data_folder, save_path)
    final_graph = add_cve_cpe_cwe(
        update_graph, recent_cves, input_data_folder, save_path
    )
    BRON_file_path = os.path.join(save_path, "BRON.json")
    with open(BRON_file_path, "w") as fd:
        json.dump(
            dict(
                nodes=[[n, final_graph.nodes[n]] for n in final_graph.nodes()],
                edges=[[u, v, final_graph.edges[u, v]] for u, v in final_graph.edges()],
            ),
            fd,
            indent=2,
        )

    assert os.path.exists(BRON_file_path)
    logging.info(f"Wrote BRON graph from {input_data_folder} to {BRON_file_path}")


def get_unique_id() -> str:
    global UNIQUE_ID
    UNIQUE_ID += 1
    id_str = str(UNIQUE_ID)
    # TODO longer zerofill
    if len(id_str) != 5:
        id_str = id_str.zfill(5)

    return id_str


def load_json(data_file: str, input_data_folder: str) -> Dict[Any, Any]:
    """
    data_file (str): data file to open, e.g. "tactic_map" or "attack_map"
    input_data_folder (str): folder path to input data

    Returns Python dictionary of JSON file using path associated with data_file
    """
    path = os.path.join(input_data_folder, NAME_MAP_PATHS[data_file])
    if path.lower().endswith(".json"):
        with open(path) as f:
            return json.load(f)
    elif path.lower().endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)

    return {}


def write_json(data_type_ids: Dict[str, str], save_path: str):
    """
    data_type_ids (dict): maps string of data type to dict of data type id to bron id,
            e.g. {"technique": technique_id_to_bron_id, "capec": capec_id_to_bron_id}
    """
    os.makedirs(BRON_PATH, exist_ok=True)
    path_start = os.path.join(save_path, BRON_PATH)
    file_paths = ID_DICT_PATHS
    for data_type, id_dict in data_type_ids.items():
        path = os.path.join(path_start, file_paths[data_type])
        with open(path, "w") as f:
            json.dump(id_dict, f)

        assert os.path.exists(path)
        logging.info(f"Wrote {data_type} to {path}")


def add_tactic_technique_edges(
    graph: "nx.Graph", input_data_folder: str, save_path: str
) -> "nx.Graph":
    logging.info(
        f"Begin adding Tactic and Technique nodes and edges from {input_data_folder}"
    )
    tactic_map = load_json("tactic_map", input_data_folder)
    technique_names = load_json("technique_names", input_data_folder)
    tactic_names = load_json("tactic_names", input_data_folder)
    with open(
        os.path.join(input_data_folder, DESCRIPTION_MAP_PATHS["technique_descriptions"])
    ) as fd:
        technique_descriptions = json.load(fd)

    with open(
        os.path.join(input_data_folder, DESCRIPTION_MAP_PATHS["tactic_descriptions"])
    ) as fd:
        tactic_descriptions = json.load(fd)

    technique_id_to_bron_id = {}
    # there are no internal tactic IDs so we map to tactic names
    # TODO why not id -> Name instead of Name -> Id for tactic?
    tactic_name_to_bron_id = {}

    # Nodes
    for tactic_name, tactic_id in tactic_names.items():
        tactic_bron_id = get_unique_id()
        tactic_node_name = "tactic_" + tactic_bron_id
        description = tactic_descriptions[tactic_id]
        short_description = description.split("\n")[0]
        graph.add_node(
            tactic_node_name,
            original_id=tactic_id,
            datatype="tactic",
            name=tactic_name,
            metadata={
                "description": description,
                "short_description": short_description,
            },
        )
        tactic_name_to_bron_id[tactic_name] = tactic_bron_id

    assert len(tactic_names) == len(tactic_name_to_bron_id)
    logging.info(f"Added {len(tactic_names)} Tactic nodes")

    for technique_id, technique_name in technique_names.items():
        technique_bron_id = get_unique_id()
        technique_node_name = "technique_" + technique_bron_id
        technique_id_to_bron_id[technique_id] = technique_bron_id
        description = technique_descriptions[technique_id]
        short_description = description.split("\n")[0]
        graph.add_node(
            technique_node_name,
            original_id=technique_id,
            datatype="technique",
            name=technique_name,
            metadata={
                "description": description,
                "short_description": short_description,
            },
        )

    assert len(technique_id_to_bron_id) == len(
        technique_names
    ), f"{len(technique_id_to_bron_id)} != {len(technique_names)}"
    logging.info(f"Added {len(technique_names)} Technique nodes")

    # Edges
    for technique in tactic_map:
        technique_original_id = technique
        if not technique_original_id:
            logging.warning(
                f"No technique id. Check upstream parsing of technique data"
            )
            continue

        technique_bron_id = technique_id_to_bron_id[technique_original_id]
        technique_node_name = "technique_" + technique_bron_id

        tactics = tactic_map[technique]
        for tactic_name in tactics:
            tactic_bron_id = tactic_name_to_bron_id[tactic_name]
            tactic_node_name = "tactic_" + tactic_bron_id
            if not graph.has_edge(tactic_node_name, technique_node_name):
                graph.add_edge(tactic_node_name, technique_node_name)
            if not graph.has_edge(technique_node_name, tactic_node_name):
                graph.add_edge(technique_node_name, tactic_node_name)

    write_json(
        {"technique": technique_id_to_bron_id, "tactic": tactic_name_to_bron_id},
        save_path,
    )
    logging.info(f"Added Technique-Tactics edges")
    return graph


def add_capec_technique_edges(
    graph: "nx.Graph", input_data_folder: str, save_path: str
) -> "nx.Graph":
    logging.info(
        f"Begin adding CAPEC and Technique nodes and edges from {input_data_folder}"
    )
    attack_map = load_json("attack_map", input_data_folder)
    capec_names = load_json("capec_names", input_data_folder)
    path = os.path.join(save_path, BRON_PATH, "technique_id_to_bron_id.json")
    with open(path, "r") as f:
        technique_id_to_bron_id = json.load(f)

    with open(
        os.path.join(input_data_folder, DESCRIPTION_MAP_PATHS["capec_descriptions"])
    ) as fd:
        capec_descriptions = json.load(fd)

    capec_id_to_bron_id = {}

    # Nodes
    for capec_id, capec_name in capec_names.items():
        capec_bron_id = get_unique_id()
        capec_node_name = "capec_" + capec_bron_id
        metadata = capec_descriptions[capec_id]
        graph.add_node(
            capec_node_name,
            original_id=capec_id,
            datatype="capec",
            name=capec_name,
            metadata=metadata,
        )
        capec_id_to_bron_id[capec_id] = capec_bron_id

    assert len(capec_names) == len(capec_id_to_bron_id)
    logging.info(f"Added {len(capec_names)} CAPEC nodes")

    # Edges
    missing_capec_technique = collections.defaultdict(list)
    for capec_original_id in attack_map:
        if capec_original_id not in capec_id_to_bron_id:
            logging.warning(
                f"CAPEC {capec_original_id} linking to {attack_map[capec_original_id]} does not exist as a node"
            )
            missing_capec_technique[capec_original_id].append(
                attack_map[capec_original_id]
            )
            continue

        capec_bron_id = capec_id_to_bron_id[capec_original_id]
        capec_node_name = "capec_" + capec_bron_id

        techniques = attack_map[capec_original_id]
        for tech in techniques:
            technique_original_id = tech
            technique_bron_id = technique_id_to_bron_id[technique_original_id]
            technique_node_name = "technique_" + technique_bron_id

            if not graph.has_edge(technique_node_name, capec_node_name):
                graph.add_edge(technique_node_name, capec_node_name)
            if not graph.has_edge(capec_node_name, technique_node_name):
                graph.add_edge(capec_node_name, technique_node_name)

    write_json({"capec": capec_id_to_bron_id}, save_path)
    logging.info(f"Added Technique-CAPEC edges")
    # TODO more information about the missing data
    logging.warning(f"Missing CAPEC-Technique links: {len(missing_capec_technique)}")
    return graph


def add_capec_cwe_edges(
    graph: "nx.Graph", input_data_folder: str, save_path: str
) -> "nx.Graph":
    logging.info(f"Begin adding CAPEC and CWE nodes and edges from {input_data_folder}")
    # make capec and cwe node and add edge between the two of them
    capec_cwe = load_json("capec_cwe", input_data_folder)
    cwe_names = load_json("cwe_names", input_data_folder)
    path = os.path.join(save_path, BRON_PATH, "capec_id_to_bron_id.json")
    with open(path, "r") as json_file:
        capec_id_to_bron_id = json.load(json_file)

    with open(
        os.path.join(input_data_folder, DESCRIPTION_MAP_PATHS["cwe_descriptions"])
    ) as fd:
        cwe_descriptions = json.load(fd)

    cwe_id_to_bron_id = {}

    for cwe_id, cwe_name in cwe_names.items():
        cwe_bron_id = get_unique_id()
        cwe_node_name = "cwe_" + cwe_bron_id
        metadata = cwe_descriptions[cwe_id]
        graph.add_node(
            cwe_node_name,
            original_id=cwe_id,
            datatype="cwe",
            name=cwe_name,
            metadata=metadata,
        )
        cwe_id_to_bron_id[cwe_id] = cwe_bron_id

    logging.info(f"Added {len(cwe_names)} CWE nodes")

    capec_cwe_pairs = capec_cwe["capec_cwe"]
    for capec_node in capec_cwe_pairs:
        capec_original_id = capec_node
        capec_bron_id = capec_id_to_bron_id[capec_original_id]
        capec_node_name = "capec_" + capec_bron_id

        cwes = capec_cwe_pairs[capec_node]["cwes"]
        for cwe in cwes:
            cwe_original_id = cwe
            cwe_bron_id = cwe_id_to_bron_id[cwe_original_id]
            cwe_node_name = "cwe_" + cwe_bron_id

            if not graph.has_edge(capec_node_name, cwe_node_name):
                graph.add_edge(capec_node_name, cwe_node_name)
            if not graph.has_edge(cwe_node_name, capec_node_name):
                graph.add_edge(cwe_node_name, capec_node_name)

    write_json({"cwe": cwe_id_to_bron_id}, save_path)
    logging.info(f"Added CWE-CAPEC edges")
    return graph


def add_cve_cpe_cwe(
    graph: "nx.Graph", recent_cves: bool, input_data_folder: str, save_path: str
) -> "nx.Graph":
    logging.info(
        f"Begin adding CVE, CPE and CWE nodes and edges from {input_data_folder}"
    )
    if recent_cves:
        cve_map = load_json("cve_map_last_five_years", input_data_folder)
        logging.info(f"Only recent CVEs")
    else:
        cve_map = load_json("cve_map", input_data_folder)

    path = os.path.join(save_path, BRON_PATH, "cwe_id_to_bron_id.json")
    with open(path, "r") as f:
        cwe_id_to_bron_id = json.load(f)
    cve_id_to_bron_id = {}
    cpe_id_to_bron_id = {}

    missing_cwe_cve = collections.defaultdict(list)
    # Edges
    for cve in cve_map:
        cve_original_id = cve
        # TODO
        if cve_original_id not in cve_id_to_bron_id:
            cve_bron_id = get_unique_id()
            cve_node_name = "cve_" + cve_bron_id
            graph.add_node(
                cve_node_name,
                datatype="cve",
                name="",
                original_id=cve_original_id,
                metadata={
                    "weight": cve_map[cve]["score"],
                    "description": cve_map[cve]["description"],
                },
            )
            cve_id_to_bron_id[cve_original_id] = cve_bron_id
        else:
            cve_bron_id = cve_id_to_bron_id[cve_original_id]
            cve_node_name = "cve_" + cve_bron_id

        for cpe in cve_map[cve]["cpes"]:
            _add_cpe_node(cpe, graph, cpe_id_to_bron_id, cve_node_name)

        for cwe in cve_map[cve]["cwes"]:
            cwe_original_id = cwe
            if not cwe.isalpha():
                if cwe_original_id not in cwe_id_to_bron_id:
                    # TODO handle CWE view and categories
                    logging.warning(
                        f"CWE {cwe_original_id} linking CVE {cve} does not exist"
                    )
                    missing_cwe_cve[cwe_original_id].append(cve)
                    continue

                cwe_bron_id = cwe_id_to_bron_id[cwe_original_id]
                cwe_node_name = "cwe_" + cwe_bron_id

                if not graph.has_edge(cwe_node_name, cve_node_name):
                    graph.add_edge(cwe_node_name, cve_node_name)
                if not graph.has_edge(cve_node_name, cwe_node_name):
                    graph.add_edge(cve_node_name, cwe_node_name)

    write_json({"cve": cve_id_to_bron_id, "cpe": cpe_id_to_bron_id}, save_path)
    logging.info(f"Added CWE-CVE-CPE edges")
    # TODO more information about the missing data
    logging.warning(f"Missing CWE-CVE links: {len(missing_cwe_cve)}")
    return graph


def parse_cpe(cpe_string: str) -> Dict[str, str]:
    # splits cpe id into product, version, vendor
    dictionary = {"product": "", "vendor": "", "version": ""}
    cpe_values = cpe_string.split("cpe:2.3:")
    dictionary["vendor"] = cpe_values[1].split(":")[1]
    dictionary["product"] = cpe_values[1].split(":")[2]
    dictionary["version"] = cpe_values[1].split(":")[3]
    return dictionary


def _add_cpe_node(
    cpe_original_id: str,
    graph: "nx.Graph",
    cpe_id_to_bron_id: Dict[str, str],
    end_point: str,
):
    if cpe_original_id not in cpe_id_to_bron_id:
        cpe_bron_id = get_unique_id()
        cpe_node_name = "cpe_" + cpe_bron_id
        cpe_meta_dict = parse_cpe(cpe_original_id)
        graph.add_node(
            cpe_node_name,
            datatype="cpe",
            name="",
            original_id=cpe_original_id,
            metadata=cpe_meta_dict,
        )
        cpe_id_to_bron_id[cpe_original_id] = cpe_bron_id
    else:
        cpe_bron_id = cpe_id_to_bron_id[cpe_original_id]
        cpe_node_name = "cpe_" + cpe_bron_id

    if not graph.has_edge(end_point, cpe_node_name):
        graph.add_edge(end_point, cpe_node_name)
    if not graph.has_edge(cpe_node_name, end_point):
        graph.add_edge(cpe_node_name, end_point)


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Create BRON graph from threat data")
    parser.add_argument(
        "--input_data_folder",
        type=str,
        required=True,
        help="Folder path to input threat data",
    )
    parser.add_argument(
        "--save_path",
        type=str,
        required=True,
        help="Folder path to save BRON graph and files, e.g. example_data/example_output_data",
    )
    parser.add_argument(
        "--only_recent_cves",
        action="store_true",
        help="Make BRON with CVEs from 2015 only",
    )
    args = vars(parser.parse_args())
    return args


def main(**args: Dict[str, Any]) -> None:
    logging.info(f"Begin build BRON with {args}")
    input_data_folder, save_path, recent_cves = args.values()
    build_graph(save_path, input_data_folder, recent_cves=recent_cves)
    logging.info(f"Done building BRON with {args}")


if __name__ == "__main__":
    log_file = os.path.basename(__file__).replace(".py", ".log")
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s",
        level=logging.INFO,
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )

    kwargs = parse_args(sys.argv[1:])
    main(**kwargs)
