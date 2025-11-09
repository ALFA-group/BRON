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


def build_graph(save_path: str, input_data_folder: str):
    logging.info(f"Begin build BRON graph from {input_data_folder}")
    main_graph = nx.DiGraph()
    tactic_graph = add_tactic_technique_edges(main_graph, input_data_folder, save_path)
    attack_graph = add_capec_technique_edges(tactic_graph, input_data_folder, save_path)
    update_graph = add_capec_cwe_edges(attack_graph, input_data_folder, save_path)
    final_graph = add_cve_cpe_cwe(update_graph, input_data_folder, save_path)
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

    with open(os.path.join(input_data_folder, DESCRIPTION_MAP_PATHS["tactic_descriptions"])) as fd:
        tactic_descriptions = json.load(fd)

    tactic_name_to_bron_id = {}

    # Nodes
    for tactic_name, tactic_id in tactic_names.items():
        description = tactic_descriptions[tactic_id]
        short_description = description.split("\n")[0]
        graph.add_node(
            tactic_id,
            original_id=tactic_id,
            datatype="tactic",
            name=tactic_name,
            metadata={
                "description": description,
                "short_description": short_description,
            },
        )
        tactic_name_to_bron_id[tactic_name] = tactic_id

    assert len(tactic_names) == len(tactic_name_to_bron_id)
    logging.info(f"Added {len(tactic_names)} Tactic nodes")

    for technique_id, technique_name in technique_names.items():
        description = technique_descriptions[technique_id]
        short_description = description.split("\n")[0]
        graph.add_node(
            technique_id,
            original_id=technique_id,
            datatype="technique",
            name=technique_name,
            metadata={
                "description": description,
                "short_description": short_description,
            },
        )

    logging.info(f"Added {len(technique_names)} Technique nodes")

    # Edges
    for technique_id in tactic_map:
        if not technique_id:
            logging.warning(f"No technique id. Check upstream parsing of technique data")
            continue

        technique_node_name = technique_id

        tactics = tactic_map[technique_id]
        for tactic_name in tactics:
            tactic_bron_id = tactic_name_to_bron_id[tactic_name]
            tactic_node_name = tactic_bron_id            
            if not graph.has_edge(tactic_node_name, technique_node_name):
                graph.add_edge(tactic_node_name, technique_node_name)
            if not graph.has_edge(technique_node_name, tactic_node_name):
                graph.add_edge(technique_node_name, tactic_node_name)

    write_json(
        {"tactic": tactic_name_to_bron_id},
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
    with open(os.path.join(input_data_folder, DESCRIPTION_MAP_PATHS["capec_descriptions"])) as fd:
        capec_descriptions = json.load(fd)

    # Nodes
    for capec_id, capec_name in capec_names.items():
        metadata = capec_descriptions[capec_id]
        graph.add_node(
            f"CA-{capec_id}",
            original_id=capec_id,
            datatype="capec",
            name=capec_name,
            metadata=metadata,
        )

    logging.info(f"Added {len(capec_names)} CAPEC nodes")

    # Edges
    for capec_id in attack_map:
        
        capec_node_name = f"CA-{capec_id}"

        techniques = attack_map[capec_id]
        for tech in techniques:
            technique_id = tech
            technique_node_name = technique_id

            if not graph.has_edge(technique_node_name, capec_node_name):
                graph.add_edge(technique_node_name, capec_node_name)
            if not graph.has_edge(capec_node_name, technique_node_name):
                graph.add_edge(capec_node_name, technique_node_name)

    logging.info(f"Added Technique-CAPEC edges")
    return graph


def add_capec_cwe_edges(
    graph: "nx.Graph", input_data_folder: str, save_path: str
) -> "nx.Graph":
    logging.info(f"Begin adding CAPEC and CWE nodes and edges from {input_data_folder}")
    # make capec and cwe node and add edge between the two of them
    capec_cwe = load_json("capec_cwe", input_data_folder)
    cwe_names = load_json("cwe_names", input_data_folder)
    
    with open(os.path.join(input_data_folder, DESCRIPTION_MAP_PATHS["cwe_descriptions"])) as fd:
        cwe_descriptions = json.load(fd)

    for cwe_id, cwe_name in cwe_names.items():
        cwe_node_name = f"CWE-{cwe_id}"
        metadata = cwe_descriptions[cwe_id]
        graph.add_node(
            cwe_node_name,
            original_id=cwe_id,
            datatype="cwe",
            name=cwe_name,
            metadata=metadata,
        )
        
    logging.info(f"Added {len(cwe_names)} CWE nodes")

    capec_cwe_pairs = capec_cwe["capec_cwe"]
    for capec_id in capec_cwe_pairs:
        capec_node_name = f"CA-{capec_id}"
        cwes = capec_cwe_pairs[capec_id]["cwes"]
        for cwe_id in cwes:
            cwe_node_name = f"CWE-{cwe_id}"

            if not graph.has_edge(capec_node_name, cwe_node_name):
                graph.add_edge(capec_node_name, cwe_node_name)
            if not graph.has_edge(cwe_node_name, capec_node_name):
                graph.add_edge(cwe_node_name, capec_node_name)

    logging.info(f"Added CWE-CAPEC edges")
    return graph


def add_cve_cpe_cwe(
    graph: "nx.Graph", input_data_folder: str, save_path: str
) -> "nx.Graph":
    logging.info(
        f"Begin adding CVE, CPE and CWE nodes and edges from {input_data_folder}"
    )
    cve_map = load_json("cve_map", input_data_folder)
    
    processed_cves = set()
    # Edges
    for cve_id in cve_map:
        # TODO
        if cve_id not in processed_cves:
            cve_node_name = cve_id
            graph.add_node(
                cve_node_name,
                datatype="cve",
                name="",
                original_id=cve_id,
                metadata={
                    "weight": cve_map[cve_id]["score"],
                    "description": cve_map[cve_id]["description"],
                    "cpes": cve_map[cve_id]["cpes"],
                    "impact": cve_map[cve_id]["impact"],
                    "exploits": cve_map[cve_id]["exploits"]
                },
            )

        for cpe_ids in cve_map[cve_id]["cpes"]: 
            for _cpe_ids in cpe_ids:
                try:
                    _add_cpe_node(_cpe_ids, graph, cve_node_name)
                except AssertionError as e:
                    logging.error(f"{e} for {cpe_ids}")                
                    raise IndexError()

        for cwe_id in cve_map[cve_id]["cwes"]:
            if not cwe_id.isalpha():
                cwe_node_name = f"CWE-{cwe_id}"
                if not graph.has_node(cwe_node_name):
                    logging.error(f"{cwe_node_name} does not exist for {cve_node_name}")
                    continue
                
                if not graph.has_edge(cwe_node_name, cve_node_name):
                    graph.add_edge(cwe_node_name, cve_node_name)
                if not graph.has_edge(cve_node_name, cwe_node_name):
                    graph.add_edge(cve_node_name, cwe_node_name)

    logging.info(f"Added CWE-CVE-CPE edges")
    # TODO more information about the missing data
    return graph


def parse_cpe(cpe_map: Dict[str, str]) -> Dict[str, str]:
    cpe_string = cpe_map['uri']
    # splits cpe id into product, version, vendor
    dictionary = {"product": "", "vendor": "", "version": ""}
    cpe_values = cpe_string.split("cpe:2.3:")
    dictionary["vendor"] = cpe_values[1].split(":")[1]
    dictionary["product"] = cpe_values[1].split(":")[2]
    dictionary["version"] = cpe_values[1].split(":")[3]
    for key, value in cpe_map.items():
        if key != 'uri':
            continue
        dictionary[key] = value
        
    return dictionary


def get_cpe_uris(e: List[Any], cpes: List[str]):
    if 'criteria' in e:
        cpes.append(e['criteria'])    
    elif 'children' in e and len(e['children']) > 0:        
        for c in e['children']:
            get_cpe_uris(c, cpes)
    elif 'cpeMatch' in e and len(e['cpeMatch']) > 0:        
        for c in e['cpeMatch']:
            get_cpe_uris(c, cpes)


def _add_cpe_node(
    cpe_list: List[Dict[str, Any]],
    graph: "nx.Graph",
    end_point: str,
):
    cpes = []
    get_cpe_uris(cpe_list, cpes)
    if len(cpes) == 0:
        logging.error(f"{len(cpes)} == 0 for {cpe_list}")
        return
    
    assert len(cpes) > 0, cpe_list
    for cpe in cpes:
        cpe_node_name = cpe
        cpe_meta_dict = parse_cpe({'uri': cpe})
        graph.add_node(
            cpe_node_name,
            datatype="cpe",
            name="",
            original_id=cpe,
            metadata=cpe_meta_dict,
        )

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
    args = vars(parser.parse_args())
    return args


def main(**args: Dict[str, Any]) -> None:
    logging.info(f"Begin build BRON with {args}")
    input_data_folder, save_path, recent_cves = args.values()
    build_graph(save_path, input_data_folder)
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
