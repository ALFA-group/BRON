import argparse
import json
import networkx as nx
import gzip
import sys
from typing import List, Dict, Any

from utils.bron_network_utils import load_graph_nodes

def load_graph_network(graph_file):
    graph_nodes, G, graph = load_graph_nodes(graph_file)
    for graph_list in graph_nodes:
        node_name = graph_list[0]
        attributes = graph_list[1]
        if not bool(attributes):
            G.add_node(node_name)
        else:
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


def count_unique_cves(graph):
    total_risk = 0
    all_nodes = graph.nodes(data=True)
    for node in all_nodes:
        if all_nodes[node[0]]["datatype"] == "cve":
            total_risk += all_nodes[node[0]]["metadata"]["weight"]
    print(total_risk)
    return total_risk


def count_unique_cves_network_specific(graph):
    total_risk = 0
    used_cves = set()
    all_nodes = graph.nodes(data=True)
    for node in all_nodes:
        if node[1]["datatype"] == "network-node":
            cpes = graph.in_edges(node[0])
            for cpe, _ in cpes:
                cves = graph.in_edges(cpe)
                for cve, _ in cves:
                    if all_nodes[cve]["datatype"] == "cve":
                        if cve not in used_cves:
                            total_risk += all_nodes[cve]["metadata"]["weight"]
                            used_cves.add(cve)
    print(total_risk)
    return total_risk


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Count number of unique CVEs")
    parser.add_argument(
        "--db_path",
        type=str,
        required=True,
        help="Location of saved BRON_db e.g. data/BRON_db/BRON_db.json or data/BRON_db/BRON_db.gz",
    )
    parser.add_argument(
        "--network_specific",
        action="store_true",
        help="Use the argument if BRON_db is network specific",
    )
    args = vars(parser.parse_args())
    return args


def main(**args: Dict[str, Any]) -> None:
    db_path, network_specific = args.values()
    graph = load_graph_network(db_path)
    if network_specific:
        count_unique_cves_network_specific(graph)
    else:
        count_unique_cves(graph)


if __name__ == "__main__":
    kwargs = parse_args(sys.argv[1:])
    main(**kwargs)
