import gzip
import json

import networkx as nx


def load_graph_nodes(graph_file):
    if graph_file.lower().endswith('.json'):
        with open(graph_file) as f:
            graph = json.load(f)
    elif graph_file.lower().endswith('.gz'):
        with gzip.open(graph_file, "rt", encoding="utf-8") as f:
            graph = json.load(f)
    G = nx.DiGraph()
    graph_nodes = graph["nodes"]
    return graph_nodes, G, graph