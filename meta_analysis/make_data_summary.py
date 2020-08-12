import networkx as nx
import argparse
import pandas as pd
import json
import gzip
import sys
from typing import List, Dict, Any

from utils.bron_network_utils import load_graph_nodes

"""
Create CSV files for specific data types with summarizing information
"""

def create_dict():
    return {
        "name": "",
        "node_name": "",
        "Edges Connected to cwe": set(),
        "Number of Edges Connected to cwe": 0,
        "Number of Edges Connected to cve": 0,
        "Edges Connected to cve": set(),
        "Edges Connected to tactic": set(),
        "Number of Edges Connected to tactic": 0,
        "Edges Connected to technique": set(),
        "Number of Edges Connected to technique": 0,
        "Edges Connected to capec": set(),
        "Number of Edges Connected to capec": 0,
        "Edges Connected to cpe": set(),
        "Number of Edges Connected to cpe": 0,
        "metadata": {},
        "original_id": "",
    }


def main_data_summary(graph, save_folder, data_types):
    """
    :param graph: BRON file
    :param save_folder: location to save summary files
    :param data_types: list of data types to make data summaries
    :return:
    """

    for dt in data_types:
        dt_list = []
        nodes = graph.nodes(data=True)
        print(dt)
        for nod in nodes:
            graph_id, nod_attributes = nod
            if nod_attributes["datatype"] == dt:
                dt_dict = create_dict()
                neighbors = graph.neighbors(graph_id)
                for neighbor in neighbors:

                    neighbor_attr = nodes[neighbor]
                    neighbor_dt = neighbor_attr["datatype"]

                    dt_dict["Edges Connected to " + neighbor_dt].add(neighbor)
                    dt_dict["Number of Edges Connected to " + neighbor_dt] += 1
                dt_dict["metadata"] = nod_attributes["metadata"]
                dt_dict["original_id"] = nod_attributes["original_id"]
                dt_dict["name"] = nod_attributes["name"]
                dt_dict["node_name"] = graph_id
                dt_list.append(dt_dict)
        df = pd.DataFrame(dt_list)
        df.to_csv(f"{save_folder}/{dt}_summary.csv")


def load_graph_network(graph_file, not_all_cpe_versions=False):
    if not_all_cpe_versions:
        cpe_nodes = latest_CPE_versions(graph_file)

    graph_nodes, G, graph = load_graph_nodes(graph_file)
    for graph_list in graph_nodes:
        node_name = graph_list[0]
        if not not_all_cpe_versions or ("cpe" not in node_name) or (node_name in cpe_nodes):
            attributes = graph_list[1]
            if not bool(attributes):
                G.add_node(node_name)
            else:
                original_id = attributes['original_id']
                datatype = attributes['datatype']
                name = attributes['name']
                metadata = attributes['metadata']
                G.add_node(node_name, original_id=original_id, datatype=datatype, name=name, metadata=metadata)

    graph_edges = graph['edges']
    for graph_list in graph_edges:
        edge_1 = graph_list[0]
        edge_2 = graph_list[1]
        if not not_all_cpe_versions or ((("cpe" not in edge_1) or (edge_1 in cpe_nodes)) and (("cpe" not in edge_2) or (edge_2 in cpe_nodes))):
            G.add_edge(edge_1, edge_2)

    return G


def latest_CPE_versions(BRON_path):
    vendor_product_to_version = dict() # maps vendor/product to latest version and node name
    latest_CPE_nodes = set() # set of node names for CPEs with latest version

    if BRON_path.lower().endswith('.json'):
        with open(BRON_path) as f:
            graph = json.load(f)
    elif BRON_path.lower().endswith('.gz'):
        with gzip.open(BRON_path, "rt", encoding="utf-8") as f:
            graph = json.load(f)

    graph_nodes = graph['nodes']
    for graph_list in graph_nodes:
        attributes = graph_list[1]
        if attributes["datatype"] == "cpe":
            vendor = attributes["metadata"]["vendor"]
            product = attributes["metadata"]["product"]
            vendor_product = f"{vendor}_{product}"
            version = attributes["metadata"]["version"]
            node_name = graph_list[0]

            if vendor_product not in vendor_product_to_version:
                vendor_product_to_version[vendor_product] = (version, node_name)
            else:
                existing_version = vendor_product_to_version[vendor_product][0]
                if version > existing_version: # check if current version is more recent
                    vendor_product_to_version[vendor_product] = (version, node_name)

    for _, version_info in vendor_product_to_version.items():
        node_name = version_info[1]
        latest_CPE_nodes.add(node_name)

    return latest_CPE_nodes


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description='Analyse network for risk')
    parser.add_argument('--BRON_path', type=str, required=True, help="Path of BRON")
    parser.add_argument('--save_folder', type=str, required=True, help="Save directory for the data summaries")
    parser.add_argument('--capec',action='store_true',help='Save data summary for capec')
    parser.add_argument('--cwe',action='store_true',help='Save data summary for cwe')
    parser.add_argument('--cve',action='store_true',help='Save data summary for cve')
    parser.add_argument('--cpe',action='store_true',help='Save data summary for cpe')
    parser.add_argument('--tactic',action='store_true',help='Save data summary for tactic')
    parser.add_argument('--technique',action='store_true',help='Save data summary for technique')
    parser.add_argument('--not_all_cpe_versions',action='store_true',help='Save data summary without all versions of CPEs')
    args = vars(parser.parse_args())
    return args


def main(**args: Dict[str, Any]) -> None:
    BRON_path, save_folder, capec, cwe, cve, cpe, tactic, technique, not_all_cpe_versions = args.values()
    graph = load_graph_network(BRON_path, not_all_cpe_versions)
    datatypes = []
    if capec:
        datatypes.append("capec")
    if cwe:
        datatypes.append("cwe")
    if cve:
        datatypes.append("cve")
    if cpe:
        datatypes.append("cpe")
    if tactic:
        datatypes.append("tactic")
    if technique:
        datatypes.append("technique")
    main_data_summary(graph, save_folder, datatypes)


if __name__ == '__main__':
    kwargs = parse_args(sys.argv[1:])
    main(**kwargs)
