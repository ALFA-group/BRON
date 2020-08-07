import argparse
import json
import pandas as pd
import csv
import networkx as nx
import gzip
import os
import sys
from typing import List, Dict, Any

from BRON_db.build_BRON_db import id_dict_paths, id_dict_network_paths
from utils.bron_network_utils import load_graph_nodes

BRON_DB_BASE_PATH = "data/BRON_db"
bron_path = os.path.join(BRON_DB_BASE_PATH, "original_id_to_bron_id")
bron_network_path = os.path.join(BRON_DB_BASE_PATH, "network_specific_BRON_db/original_id_to_bron_id")
id_dict_network_paths["network-node"] = "network_name_to_bron_id.json"
out_order = {"tactic": "technique", "technique": "capec", "capec": "cwe",
             "cwe": "cve", "cve": "cpe"}
in_order = {"technique": "tactic", "capec": "technique", "cwe": "capec",
            "cve": "cwe", "cpe": "cve"}
order = {"out": out_order, "in": in_order} # order of data types for edges

def get_data(data_file):
    # find the input data
    data_dict = {}
    if ".csv" not in data_file:
        raise Exception("This {} file is not in CSV format".format(data_file))
    with open(data_file, "r") as csvfile:
        # creating a csv reader object
        csvreader = csv.reader(csvfile)

        # extracting field names through first row
        for row in csvreader:
            if len(row) > 1:
                for num in row:
                    if num not in data_dict.keys():
                        data_dict[num] = 1
                    else:
                        data_dict[num] += 1

    return data_dict


def count_total(graph, network_specific):
    threat_info_count = {
        "technique": 0,
        "tactic": 0,
        "attack": 0,
        "capec": 0,
        "cwe": 0,
        "cve": 0,
        "risk_score": 0,
        "cpe": 0,
    }
    if network_specific:
        threat_info_count["network-node"] = 0
    nodes = graph.nodes(data=True)
    for nod in nodes:
        nod_type = nodes[nod[0]]["datatype"]
        threat_info_count[nod_type] += 1
        if "cve" == nod_type:
            threat_info_count["risk_score"] += nodes[nod[0]]["metadata"]["weight"]
    return threat_info_count


def make_threat_info_dict(network_specific):
    threat_info_dict = {
        "tactic": set(),
        "technique": set(),
        "capec": set(),
        "cwe": set(),
        "cve": set(),
        "risk_score": 0,
        "cpe": set(),
    }
    if network_specific:
        threat_info_dict["network-node"] = set()

    return threat_info_dict


def _append_node(edge_dict, n_1, n_2, cve_list, next_node_type, node, all_nodes):
    if (next_node_type == "cpe" and "cve_" in node) or (
            "cpe_" in node and next_node_type == "cve"
    ):
        if "cve_" in n_1:
            if n_1 not in cve_list:
                edge_dict["risk_score"] += all_nodes[n_1]["metadata"]["weight"]
                cve_list.append(n_1)
        else:
            if n_2 not in cve_list:
                edge_dict["risk_score"] += all_nodes[n_2]["metadata"]["weight"]
                cve_list.append(n_2)


def add_edges(node, next_node_type, edge_dict, graph, node_direction, cve_list):
    if node_direction == "in":
        node_2_edges = graph.in_edges(node)

    elif node_direction == "out":
        node_2_edges = graph.out_edges(node)
    all_nodes = graph.nodes(data=True)
    for n_1, n_2 in node_2_edges:
        if next_node_type + "_" in n_1:
            edge_dict[next_node_type].add(n_1)
            _append_node(edge_dict, n_1, n_2, cve_list, next_node_type, node, all_nodes)
        elif next_node_type + "_" in n_2:
            edge_dict[next_node_type].add(n_2)
            _append_node(edge_dict, n_1, n_2, cve_list, next_node_type, node, all_nodes)

    return edge_dict, cve_list


def make_dicts(data_type, network_specific):
    if (data_type == "network-node") or network_specific:
        path = os.path.join(bron_network_path, id_dict_network_paths[data_type])
    else:
        path = os.path.join(bron_path, id_dict_paths[data_type])
    with open(path) as f:
        bron_dict = json.load(f)

    threat_info_dict = make_threat_info_dict(network_specific)
    return bron_dict, threat_info_dict


def make_graph_edges_helper(data_type, name, edge_dict, graph, direction, cve_list):
    """
    direction (str): either "out" or "in"
    """
    next_type = order[direction][data_type] # e.g. direction = "in", data_type = "capec", next_type = "technique"
    edge_dict, cve_list = add_edges(
        name, next_type, edge_dict, graph, direction, cve_list
    )

    while next_type in order[direction].keys():
        next_next_type = order[direction][next_type] # e.g. direction = "in", next_next_type = "tactic"
        for key in edge_dict[next_type]:
            edge_dict, cve_list = add_edges(
                key, next_next_type, edge_dict, graph, direction, cve_list
            )
        next_type = next_next_type

    return edge_dict, cve_list


def make_graph_edges(data_key, data_type, bron_dict, edge_dict, graph, rows_list, network_specific):
    """
    data_key: refers to tactic, technique, etc (not a str)
    data_type (str): one of "tactic", "technique", "capec", "cwe", "cve", "cpe" but not "network-node"
    """
    if data_key in bron_dict:
        cve_list = []
        bron_id = bron_dict[data_key]
        name = data_type + "_" + bron_id
        edge_dict[data_type].add(name)

        if data_type != "cpe":
            edge_dict, cve_list = make_graph_edges_helper(data_type, name, edge_dict, graph, "out", cve_list)
        if network_specific:
            for cpe in edge_dict["cpe"]:
                edge_dict, cve_list = add_edges(
                    cpe, "network-node", edge_dict, graph, "out", cve_list
                )

        if data_type != "tactic":
            edge_dict, cve_list = make_graph_edges_helper(data_type, name, edge_dict, graph, "in", cve_list)

        rows_list.append(edge_dict)

    return rows_list


# returns list of paths from starting point separated by different threat data types
def get_chain(data, graph, data_type, length, network_specific):
    rows_list = []
    if data_type == "tactic":
        for tactic in data.keys():
            bron_dict, threat_info_dict = make_dicts(data_type, network_specific)
            rows_list = make_graph_edges(tactic, data_type, bron_dict, threat_info_dict, graph, rows_list, network_specific)

    if data_type == "technique":
        for technique in data.keys():
            bron_dict, threat_info_dict = make_dicts(data_type, network_specific)
            rows_list = make_graph_edges(technique, data_type, bron_dict, threat_info_dict, graph, rows_list, network_specific)

    if data_type == "capec":
        for capec in data.keys():
            bron_dict, threat_info_dict = make_dicts(data_type, network_specific)
            rows_list = make_graph_edges(capec, data_type, bron_dict, threat_info_dict, graph, rows_list, network_specific)

    elif data_type == "cwe":
        for cwe in data.keys():
            bron_dict, threat_info_dict = make_dicts(data_type, network_specific)
            rows_list = make_graph_edges(cwe, data_type, bron_dict, threat_info_dict, graph, rows_list, network_specific)

    elif data_type == "cve":
        for cve in data.keys():
            bron_dict, threat_info_dict = make_dicts(data_type, network_specific)
            rows_list = make_graph_edges(cve, data_type, bron_dict, threat_info_dict, graph, rows_list, network_specific)

    elif data_type == "cpe":
        for cpe in data.keys():
            bron_dict, threat_info_dict = make_dicts(data_type, network_specific)
            rows_list = make_graph_edges(cpe, data_type, bron_dict, threat_info_dict, graph, rows_list, network_specific)

    elif data_type == "network-node":
        for net_node in data.keys():
            bron_dict, threat_info_dict = make_dicts(data_type, network_specific)
            if net_node in id_dict_network_paths:
                net_node_bron_id = id_dict_network_paths[net_node]
                net_node_name = "network-node" + net_node_bron_id
                threat_info_dict["network-node"].add(net_node_name)
                cve_list = []
                threat_info_dict, cve_list = add_edges(
                    net_node_name, "cpe", threat_info_dict, graph, "in", cve_list
                )
                for cpe in threat_info_dict["cpe"]:
                    threat_info_dict, cve_list = add_edges(
                        cpe, "cve", threat_info_dict, graph, "in", cve_list
                    )
                for cve in threat_info_dict["cve"]:
                    threat_info_dict, cve_list = add_edges(
                        cve, "cwe", threat_info_dict, graph, "in", cve_list
                    )
                for cwe in threat_info_dict["cwe"]:
                    threat_info_dict, cve_list = add_edges(
                        cwe, "capec", threat_info_dict, graph, "in", cve_list
                    )
                for capec in threat_info_dict["capec"]:
                    threat_info_dict, cve_list = add_edges(
                        capec, "technique", threat_info_dict, graph, "in", cve_list
                    )
                for technique in threat_info_dict["technique"]:
                    threat_info_dict, cve_list = add_edges(
                        technique, "tactic", threat_info_dict, graph, "in", cve_list
                    )
                rows_list.append(threat_info_dict)
    if length:
        for i in range(len(rows_list)):
            for k in rows_list[i].keys():
                if type(rows_list[i][k]) == set:
                    if data_type not in k:
                        rows_list[i][k] = len(rows_list[i][k])
    total = count_total(graph, network_specific)
    rows_list.append(total)
    df = pd.DataFrame(rows_list)
    new_column = []
    for i in range(len(df["capec"]) - 1):
        new_column.append("connected")
    new_column.append("Total Number")
    df["Node Type"] = new_column
    return df


def load_graph_network(graph_file):
    graph_nodes, G, graph = load_graph_nodes(graph_file)
    for graph_list in graph_nodes:
        node_name = graph_list[0]
        attributes = graph_list[1]
        original_id = attributes["original_id"]
        datatype = attributes["datatype"]
        name = attributes["name"]
        metadata = attributes["metadata"]

        G.add_node(
            node_name,
            original_id=original_id,
            datatype=datatype,
            name=name,
            metadata=metadata,
        )
    graph_edges = graph["edges"]
    for graph_list in graph_edges:
        edge_1 = graph_list[0]
        edge_2 = graph_list[1]
        G.add_edge(edge_1, edge_2)

    return G


def main_attack(network, args_file, results_name, arg_type, length, network_specific):
    graph = load_graph_network(network)
    data = get_data(args_file)
    network_data_frame = get_chain(data, graph, arg_type, length, network_specific)
    network_data_frame.to_csv(results_name)
    return network_data_frame


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Analyse network for risk")
    parser.add_argument(
        "--db_path",
        type=str,
        required=True,
        help="Path to BRON_db e.g. data/graph/graph_results/threat_data.json",
    )
    parser.add_argument(
        "--length",
        action="store_true",
        help="True if only want the path results to show the number of CVEs, CPEs, etc instead of the actual IDs",
    )
    parser.add_argument(
        "--network_specific",
        action="store_true",
        help="True if BRON_db is network specific",
    )
    parser.add_argument(
        "--starting_point",
        type=str,
        required=True,
        help="Path to file that contains the data (CAPEC, ATT&CK, CVE, CPE, CWE) that were used in the attack. Values should be separated by commas",
    )
    parser.add_argument(
        "--results_file",
        type=str,
        required=True,
        help="Name of file to store results in",
    )
    parser.add_argument(
        "--starting_point_type",
        type=str,
        required=True,
        help="Type of attack arguments: one of Tactic, Technique, CAPEC, CVE, CWE, CPE or Network-Node (if network specific BRON_db)",
    )
    args = vars(parser.parse_args())
    return args


def main(**args: Dict[str, Any]) -> None:
    db_path, length, network_specific, starting_point, results_file, starting_point_type = args.values()
    main_attack(db_path, starting_point, results_file, starting_point_type, length, network_specific)


if __name__ == "__main__":
    kwargs = parse_args(sys.argv[1:])
    main(**kwargs)
