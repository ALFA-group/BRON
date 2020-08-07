import json
import networkx as nx


UNIQUE_ID = 0


def get_unique_id():
    global UNIQUE_ID
    UNIQUE_ID += 1
    id_str = str(UNIQUE_ID)
    if len(id_str) != 5:
        id_str = id_str.zfill(5)
    return id_str


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
