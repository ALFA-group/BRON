import json
import csv
import gzip
import re

import networkx as nx


UNIQUE_ID = 0
ta_re_pattern = "TA00\d{2}"
ta_prog = re.compile(ta_re_pattern)
t_re_pattern = "(T\d{4}(\.\d{3})?)"
t_prog = re.compile(t_re_pattern)
cve_re_pattern = "CVE-\d{4}-\d{4,7}"
cve_prog = re.compile(cve_re_pattern)


def get_unique_id():
    global UNIQUE_ID
    UNIQUE_ID += 1
    id_str = str(UNIQUE_ID)
    if len(id_str) != 5:
        id_str = id_str.zfill(5)
    return id_str


def load_graph_nodes(graph_file):
    if graph_file.lower().endswith(".json"):
        with open(graph_file) as f:
            graph = json.load(f)
    elif graph_file.lower().endswith(".gz"):
        with gzip.open(graph_file, "rt", encoding="utf-8") as f:
            graph = json.load(f)
    G = nx.DiGraph()
    graph_nodes = graph["nodes"]
    return graph_nodes, G, graph


def load_graph_network(graph_file):
    with open(graph_file) as f:
        graph = json.load(f)
    G = nx.DiGraph()
    graph_nodes = graph["nodes"]
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


def save_graph(G, fname):
    with open(fname, "w") as f:
        graph_dict = dict(
            nodes=[[n, G.nodes[n]] for n in G.nodes()],
            edges=[[u, v, G.edges[u, v]] for u, v in G.edges()],
        )
        json.dump(graph_dict, f, indent=2)


def get_csv_data(data_file):
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
