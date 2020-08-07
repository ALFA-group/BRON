import argparse
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
            weight = attributes["weight"]
            G.add_node(node_name, weight=weight)
    graph_edges = graph["edges"]
    for graph_list in graph_edges:
        edge_1 = graph_list[0]
        edge_2 = graph_list[1]
        attributes = graph_list[2]
        if not bool(attributes):
            G.add_edge(edge_1, edge_2)
        else:
            weight = attributes["weight"]
            G.add_edge(edge_1, edge_2, weight=weight)
    return G


def riskiest_node(graph):
    highest_score = -1
    highest_software = set()
    all_nodes = graph.nodes
    for node in all_nodes:
        score = 0
        used_cves = set()
        if "net_node_" in node:
            cpes = graph.in_edges(node)
            for cpe, _ in cpes:
                cves = graph.in_edges(cpe)
                for cve, _ in cves:
                    if cve not in used_cves:
                        score += all_nodes[cve]["weight"]
                        used_cves.add(cve)
                        if score >= highest_score:
                            highest_score = score
                            highest_software.add(node)
    print(highest_score, highest_software)
    return highest_score, highest_software


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Find riskiest software for network")
    parser.add_argument(
        "--db_path",
        type=str,
        required=True,
        help="Location of network specific db large_network_BRON_db e.g. data/BRON_db/network_specific_BRON_db/large_network_BRON_db.json or data/BRON_db/network_specific_BRON_db/large_network_BRON_db.gz",
    )
    args = vars(parser.parse_args())
    return args


def main(**args: Dict[str, Any]) -> None:
    db_path = args.values()
    graph = load_graph_network(db_path)
    riskiest_node(graph)


if __name__ == "__main__":
    kwargs = parse_args(sys.argv[1:])
    main(**kwargs)
