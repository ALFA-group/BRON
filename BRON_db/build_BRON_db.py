import networkx as nx
import argparse
import json
import gzip
import os
import sys
from typing import List, Dict, Any

UNIQUE_ID = 0
BRON_DB_BASE_PATH = "data/BRON_db"
BRON_DB_PATH = os.path.join(BRON_DB_BASE_PATH, "original_id_to_bron_id")
BRON_DB_NETWORK_PATH = os.path.join(BRON_DB_BASE_PATH, "network_specific_BRON_db/original_id_to_bron_id")
name_map_paths = {"tactic_map": "technique_tactic_map.json",
                  "technique_names": "technique_name_map.json",
                  "attack_map": "capec_technique_map.json",
                  "capec_names": "capec_names.json",
                  "capec_cwe": "capec_cwe_mapping.json",
                  "cwe_names": "cwe_names.json",
                  "cve_map": "cve_map_cpe_cwe_score.json",
                  "cve_map_2015_2020": "cve_map_cpe_cwe_score_2015_2020.json"}
id_dict_paths = {"tactic": "tactic_name_to_bron_id.json",
                 "technique": "technique_id_to_bron_id.json",
                 "capec": "capec_id_to_bron_id.json",
                 "cwe": "cwe_id_to_bron_id.json",
                 "cve": "cve_id_bron_id.json",
                 "cpe": "cpe_id_bron_id.json",
                 "network": "network_name_to_bron_id.json"}
id_dict_network_paths = {"tactic": "tactic_name_to_bron_id.json",
                         "technique": "technique_id_to_bron_id.json",
                         "capec": "capec_id_to_bron_id.json",
                         "cwe": "cwe_id_to_bron_id.json",
                         "cve": "cve_id_to_bron_id.json",
                         "cpe": "cpe_id_to_bron_id.json",
                         "network": "network_name_to_bron_id.json"}

def build_graph(graph_path, input_data_folder, network=None, recent_cves=False):
    main_graph = nx.DiGraph()
    tactic_graph = add_tactic_technique_edges(main_graph, network, input_data_folder)
    attack_graph = add_capec_technique_edges(tactic_graph, network, input_data_folder)
    update_graph = add_capec_cwe_edges(attack_graph, network, input_data_folder)

    if network is not None:
        cpe_graph = add_cve_cpe_cwe(update_graph, recent_cves, network, input_data_folder)
        final_graph = connect_cpe_network_nodes(cpe_graph, network)
    else:
        final_graph = add_cve_cpe_cwe(update_graph, recent_cves, input_data_folder)

    save(final_graph, graph_path)


def save(G, fname):
    json.dump(
        dict(
            nodes=[[n, G.node[n]] for n in G.nodes()],
            edges=[[u, v, G.edges[u, v]] for u, v in G.edges()],
        ),
        open(fname, "w"),
        indent=2,
    )


def get_unique_id():
    global UNIQUE_ID
    UNIQUE_ID += 1
    id_str = str(UNIQUE_ID)
    if len(id_str) != 5:
        id_str = id_str.zfill(5)
    return id_str


def load_json(data_file, input_data_folder):
    """
    data_file (str): data file to open, e.g. "tactic_map" or "attack_map"

    Returns Python dictionary of JSON file using path associated with data_file
    """
    PATH = os.path.join(input_data_folder, name_map_paths[data_file])
    if PATH.lower().endswith('.json'):
        with open(PATH) as f:
            return json.load(f)
    elif PATH.lower().endswith('.gz'):
        with gzip.open(PATH, "rt", encoding="utf-8") as f:
            return json.load(f)


def write_json(data_type_ids, network):
    """
    data_type_ids (dict): maps string of data type to dict of data type id to bron id,
            e.g. {"technique": technique_id_to_bron_id, "capec": capec_id_to_bron_id}
    """
    if network is not None:
        path_start = BRON_DB_NETWORK_PATH
        file_paths = id_dict_network_paths
    else:
        path_start = BRON_DB_PATH
        file_paths = id_dict_paths

    for data_type, id_dict in data_type_ids.items():
        PATH = os.path.join(path_start, file_paths[data_type])
        with open (PATH, "w") as f:
            json.dump(id_dict, f)


def add_tactic_technique_edges(graph, network, input_data_folder):
    tactic_map = load_json("tactic_map", input_data_folder)
    technique_names = load_json("technique_names", input_data_folder)
    technique_id_to_bron_id = {}
    # there are no internal tactic IDs so we map to tactic names
    tactic_name_to_bron_id = {}
    for technique in tactic_map:
        technique_original_id = technique
        if technique_original_id not in technique_id_to_bron_id:
            technique_bron_id = get_unique_id()
            technique_node_name = "technique_" + technique_bron_id
            technique_id_to_bron_id[technique_original_id] = technique_bron_id
            graph.add_node(
                technique_node_name,
                original_id=technique_original_id,
                datatype="technique",
                name=technique_names[technique_original_id],
                metadata={},
            )
        else:
            technique_bron_id = technique_id_to_bron_id[technique_original_id]
            technique_node_name = "technique_" + technique_bron_id

        tactics = tactic_map[technique]
        for tact in tactics:
            tactic_name = tact

            if tactic_name not in tactic_name_to_bron_id:
                tactic_bron_id = get_unique_id()
                tactic_node_name = "tactic_" + tactic_bron_id
                graph.add_node(
                    tactic_node_name,
                    original_id="",
                    datatype="tactic",
                    name=tact,
                    metadata={},
                )
                tactic_name_to_bron_id[tact] = tactic_bron_id
            else:
                tactic_bron_id = tactic_name_to_bron_id[tactic_name]
                tactic_node_name = "tactic_" + tactic_bron_id
            if not graph.has_edge(tactic_node_name, technique_node_name):
                graph.add_edge(tactic_node_name, technique_node_name)
            if not graph.has_edge(technique_node_name, tactic_node_name):
                graph.add_edge(technique_node_name, tactic_node_name)
    write_json({"technique": technique_id_to_bron_id, "tactic": tactic_name_to_bron_id}, network)
    return graph


def add_capec_technique_edges(graph, network, input_data_folder):
    attack_map = load_json("attack_map", input_data_folder)
    capec_names = load_json("capec_names", input_data_folder)
    technique_names = load_json("technique_names", input_data_folder)
    if network is not None:
        path = os.path.join(BRON_DB_NETWORK_PATH, "technique_id_to_bron_id.json")
    else:
        path = os.path.join(BRON_DB_PATH, "technique_id_to_bron_id.json")
    with open(path, "r") as f:
        technique_id_to_bron_id = json.load(f)
    capec_id_to_bron_id = {}
    for capec in attack_map:

        capec_original_id = capec

        if capec_original_id not in capec_id_to_bron_id:
            if capec_original_id in capec_names:
                capec_real_name = capec_names[capec_original_id]
            else:
                capec_real_name = "Name not found"
            capec_bron_id = get_unique_id()
            capec_node_name = "capec_" + capec_bron_id
            graph.add_node(
                capec_node_name,
                original_id=capec_original_id,
                datatype="capec",
                name=capec_real_name,
                metadata={},
            )
            capec_id_to_bron_id[capec_original_id] = capec_bron_id

        else:
            capec_bron_id = capec_id_to_bron_id[capec_original_id]
            capec_node_name = "capec_" + capec_bron_id

        techniques = attack_map[capec]
        for tech in techniques:
            technique_original_id = tech
            if technique_original_id not in technique_id_to_bron_id:
                technique_bron_id = get_unique_id()
                technique_node_name = "technique_" + technique_bron_id
                if technique_original_id in technique_names:
                    technique_actual_name = technique_names[technique_original_id]
                else:
                    technique_actual_name = "Name not found"
                graph.add_node(
                    technique_node_name,
                    original_id=technique_original_id,
                    datatype="technique",
                    name=technique_actual_name,
                    metadata={},
                )
                technique_id_to_bron_id[technique_original_id] = technique_bron_id
            else:
                technique_bron_id = technique_id_to_bron_id[technique_original_id]
                technique_node_name = "technique_" + technique_bron_id

            if not graph.has_edge(technique_node_name, capec_node_name):
                graph.add_edge(technique_node_name, capec_node_name)
            if not graph.has_edge(capec_node_name, technique_node_name):
                graph.add_edge(capec_node_name, technique_node_name)
    write_json({"technique": technique_id_to_bron_id, "capec": capec_id_to_bron_id}, network)
    return graph


def add_capec_cwe_edges(graph, network, input_data_folder):
    # make capec and cwe node and add edge between the two of them
    capec_cwe = load_json("capec_cwe", input_data_folder)
    capec_names = load_json("capec_names", input_data_folder)
    cwe_names = load_json("cwe_names", input_data_folder)
    if network is not None:
        path = os.path.join(BRON_DB_NETWORK_PATH, "capec_id_to_bron_id.json")
    else:
        path = os.path.join(BRON_DB_PATH, "capec_id_to_bron_id.json")
    with open(path, "r") as json_file:
        capec_id_to_bron_id = json.load(json_file)
    cwe_id_to_bron_id = {}
    capec_cwe_pairs = capec_cwe["capec_cwe"]
    for capec_node in capec_cwe_pairs:
        capec_original_id = capec_node
        if capec_original_id not in capec_id_to_bron_id:
            capec_bron_id = get_unique_id()
            capec_node_name = "capec_" + capec_bron_id
            if capec_original_id in capec_names:
                capec_real_name = capec_names[capec_original_id]
            else:
                capec_real_name = "Name not found"
            graph.add_node(
                capec_node_name,
                original_id=capec_original_id,
                datatype="capec",
                name=capec_real_name,
                metadata={},
            )
            capec_id_to_bron_id[capec_original_id] = capec_bron_id
        else:
            capec_bron_id = capec_id_to_bron_id[capec_original_id]
            capec_node_name = "capec_" + capec_bron_id

        cwes = capec_cwe_pairs[capec_node]["cwes"]
        for cwe in cwes:
            cwe_original_id = cwe
            if cwe_original_id not in cwe_id_to_bron_id:
                cwe_bron_id = get_unique_id()
                cwe_node_name = "cwe_" + cwe_bron_id
                if cwe_original_id in cwe_names:
                    cwe_real_name = cwe_names[cwe_original_id]
                else:
                    cwe_real_name = ""
                graph.add_node(
                    cwe_node_name,
                    original_id=cwe_original_id,
                    datatype="cwe",
                    name=cwe_real_name,
                    metadata={},
                )
                cwe_id_to_bron_id[cwe_original_id] = cwe_bron_id

            else:
                cwe_bron_id = cwe_id_to_bron_id[cwe_original_id]
                cwe_node_name = "cwe_" + cwe_bron_id
            if not graph.has_edge(capec_node_name, cwe_node_name):
                graph.add_edge(capec_node_name, cwe_node_name)
            if not graph.has_edge(cwe_node_name, capec_node_name):
                graph.add_edge(cwe_node_name, capec_node_name)
    write_json({"capec": capec_id_to_bron_id, "cwe": cwe_id_to_bron_id}, network)
    return graph


def add_cve_cpe_cwe(graph, recent_cves, input_data_folder, network=None):
    if recent_cves:
        cve_map = load_json("cve_map_2015_2020", input_data_folder)
    else:
        cve_map = load_json("cve_map", input_data_folder)
    cwe_names = load_json("cwe_names", input_data_folder)
    if network is not None:
        path = os.path.join(BRON_DB_NETWORK_PATH, "cwe_id_to_bron_id.json")
    else:
        path = os.path.join(BRON_DB_PATH, "cwe_id_to_bron_id.json")
    with open(path, "r") as f:
        cwe_id_to_bron_id = json.load(f)
    cve_id_to_bron_id = {}
    cpe_id_to_bron_id = {}
    for cve in cve_map:
        cve_original_id = cve
        if cve_original_id not in cve_id_to_bron_id:
            cve_bron_id = get_unique_id()
            cve_node_name = "cve_" + cve_bron_id
            graph.add_node(cve_node_name, datatype="cve", name="", original_id=cve_original_id,
                           metadata={"weight": cve_map[cve]["score"], "description": cve_map[cve]["description"]})
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
                    cwe_bron_id = get_unique_id()
                    cwe_node_name = "cwe_" + cwe_bron_id
                    if cwe_original_id in cwe_names:
                        cwe_real_name = cwe_names[cwe_original_id]
                    else:
                        cwe_real_name = "Name not found"
                    graph.add_node(cwe_node_name, datatype="cwe", original_id=cwe_original_id, name=cwe_real_name, metadata={})
                    cwe_id_to_bron_id[cwe_original_id] = cwe_bron_id
                else:
                    cwe_bron_id = cwe_id_to_bron_id[cwe_original_id]
                    cwe_node_name = "cwe_" + cwe_bron_id

                if not graph.has_edge(cwe_node_name, cve_node_name):
                    graph.add_edge(cwe_node_name, cve_node_name)
                if not graph.has_edge(cve_node_name, cwe_node_name):
                    graph.add_edge(cve_node_name, cwe_node_name)
    write_json({"cwe": cwe_id_to_bron_id, "cve": cve_id_to_bron_id, "cpe": cpe_id_to_bron_id}, network)
    return graph


def parse_cpe(cpe_string):
    # splits cpe id into product, version, vendor
    dictionary = {"product": "", "vendor": "", "version": ""}
    cpe_values = cpe_string.split("cpe:2.3:")
    dictionary["vendor"] = cpe_values[1].split(":")[1]
    dictionary["product"] = cpe_values[1].split(":")[2]
    dictionary["version"] = cpe_values[1].split(":")[3]
    return dictionary


def _add_cpe_node(cpe, graph, cpe_id_to_bron_id, end_point):
    cpe_original_id = cpe
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


def connect_cpe_network_nodes(graph, network):
    with open(network) as f:
        net = json.load(f)
    with open(
        os.path.join(BRON_DB_PATH, "cpe_id_to_bron_id.json"),
        "r",
    ) as json_file:
        cpe_id_to_bron_id = json.load(json_file)
    network_name_to_bron_id = {}
    for level in net.keys():
        second_level = net[level]
        for node in second_level:

            third_level = second_level[node]
            for named_node in third_level:

                net_node_bron_id = get_unique_id()

                node = third_level[named_node]
                net_node_name = "network-node_" + net_node_bron_id
                net_node_real_name = named_node
                if net_node_real_name not in network_name_to_bron_id:
                    graph.add_node(
                        net_node_name,
                        original_id="",
                        name=net_node_real_name,
                        datatype="network-node",
                        metadata={},
                    )
                    network_name_to_bron_id[net_node_real_name] = net_node_bron_id
                else:
                    net_node_real_name = named_node
                    net_node_bron_id = network_name_to_bron_id[net_node_real_name]
                    net_node_name = "network-node_" + net_node_bron_id
                for app in node:
                    cpe = node[app]
                    _add_cpe_node(cpe, graph, cpe_id_to_bron_id, net_node_name)

    write_json({"cpe": cpe_id_to_bron_id, "network": network_name_to_bron_id}, network)
    return graph


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Create graph from threat data")
    parser.add_argument('--data_folder', type=str, required=True, help='Folder containing parsed data e.g. data/example_data')
    parser.add_argument('--save_path', type=str, required=True,
                        help='Path to save graph e.g. data/graph/graph_results/threat_data.json')
    parser.add_argument('--only_recent_cves', action='store_true', help='Make BRON_db with CVEs from 2015 to 2020 only')
    args = vars(parser.parse_args())
    return args


def main(**args: Dict[str, Any]) -> None:
    input_data_folder, save_path, recent_cves = args.values()
    build_graph(save_path, input_data_folder, recent_cves=recent_cves)


if __name__ == "__main__":
    kwargs = parse_args(sys.argv[1:])
    main(**kwargs)
