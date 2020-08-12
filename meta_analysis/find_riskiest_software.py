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


def riskiest_software(graph):
    highest_score = -1
    highest_software = set()
    all_nodes = graph.nodes(data=True)
    for node in all_nodes:
        score = 0
        if "cpe_" in node[0]:
            cves = graph.in_edges(node[0])
            for cve, _ in cves:
                score += all_nodes[cve]["metadata"]["weight"]
            if score >= highest_score:
                highest_score = score
                highest_software.add(node[1]["metadata"]["product"])
    print(highest_score, highest_software)
    return highest_score, highest_software


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Find riskiest software")
    parser.add_argument(
        "--BRON_path",
        type=str,
        required=True,
        help="File path to saved BRON, e.g. data/BRON.json",
    )
    args = vars(parser.parse_args())
    return args


def main(**args: Dict[str, Any]) -> None:
    BRON_path = args.values()
    graph = load_graph_network(BRON_path)
    riskiest_software(graph)


if __name__ == "__main__":
    kwargs = parse_args(sys.argv[1:])
    main(**kwargs)
