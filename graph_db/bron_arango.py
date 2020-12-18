from typing import Dict, List, Tuple
import collections
import os
import json
import sys
import argparse

import arango

from meta_analysis.find_riskiest_software import load_graph_network

# Use arango via docker and python-arango package

# TODO have in and out edges? Now only one direction is used

MAX_ELEMENTS = 1000
DB = "BRON"
GRAPH = "BRONGraph"
USER = "root"
HOST = f"http://{os.environ.get('BRON_ARANGO_IP', 'localhost')}:8529"
PWD = os.environ.get("BRON_ARANGO_PWD", "")
NODE_KEYS = ("tactic", "technique", "capec", "cwe", "cve", "cpe")
EDGE_KEYS = (("tactic", "technique"),
             ("technique", "capec"),
             ("capec", "cwe"),
             ("cwe", "cve"),
             ("cve", "cpe"),
             )


def get_edge_keys() -> List[Tuple[str, str]]:
    edge_keys = list(EDGE_KEYS)
    for item in EDGE_KEYS:
        item_list = list(item)
        item_list.reverse()
        edge_keys.append(tuple(item_list))

    return edge_keys


def main(bron_file_path: str) -> None:
    create_db()
    host = f"http://{os.environ.get('BRON_ARANGO_IP', 'localhost')}:8529"
    print(host)
    client = arango.ArangoClient(hosts=host)
    db = client.db(DB, username=USER, password=PWD, auth_method="basic")
    
    if not db.has_graph(GRAPH):
        bron_graph = db.create_graph(GRAPH)
    else:
        bron_graph = db.graph(GRAPH)

    edge_keys = get_edge_keys()    
    edge_file_handles = {}
    for edge_key in edge_keys:
        edge_collection_key = get_edge_collection_name(*edge_key)
        edge_file_handles[edge_collection_key] = open(f"{edge_collection_key}.json", "w")
        if bron_graph.has_edge_definition(edge_collection_key):
            _ = bron_graph.edge_collection(edge_collection_key)
        else:
            _ = bron_graph.create_edge_definition(
                edge_collection=edge_collection_key,
                from_vertex_collections=[edge_key[0]],
                to_vertex_collections=[edge_key[1]]
            )
        print(f"Done: {edge_collection_key}")

    node_file_handles = {}
    for collection in NODE_KEYS:
        node_file_handles[collection] = open(f"{collection}.json", 'w')
        
        print(f"Done: {collection}")
        
    # Load data
    nx_bron_graph = load_graph_network(bron_file_path)
    print("Loaded nx")
    # Insert nodes
    nodes_nx = nx_bron_graph.nodes(data=True)
    for cnt, node in enumerate(nodes_nx):
        document = {"_key": node[0]}
        document.update(node[1])
        node_key = get_node_key(node[0])
        json.dump(document, node_file_handles[node_key])
        node_file_handles[node_key].write("\n")

    _ = [_.close() for _ in node_file_handles.values()]
    print(f"Done: Nodes")
    # Insert edges
    edges_nx = nx_bron_graph.edges()
    for cnt, edge in enumerate(edges_nx):
        from_node_key = get_node_key(edge[0])
        from_ = f"{from_node_key}/{edge[0]}"
        to_node_key = get_node_key(edge[1])
        to_ = f"{to_node_key}/{edge[1]}"
        edge_collection_key = get_edge_collection_name(to_node_key, from_node_key)
        document = {'_id': f"{edge_collection_key}/{edge[0]}-{edge[1]}", '_from': from_, '_to':to_}
        json.dump(document, edge_file_handles[edge_collection_key])
        edge_file_handles[edge_collection_key].write("\n")
        
    _ = [_.close() for _ in edge_file_handles.values()]
    print(f"Done: Edges")

    
def get_node_key(name: str) -> str:
    return name.split('_')[0]

def get_edge_collection_name(to_collection: str, from_collection: str) -> str:
    return f"{to_collection.capitalize()}{from_collection.capitalize()}"


def create_db() -> None:
    host = f"http://{os.environ.get('BRON_ARANGO_IP', 'localhost')}:8529"
    print(host)
    client = arango.ArangoClient(hosts=host)
    sys_db = client.db('_system', username=USER, password=PWD, auth_method="basic")
    if not sys_db.has_database(DB):
        sys_db.create_database(DB)

def create_guest_user() -> None:
    GUEST = 'guest'
    client = arango.ArangoClient(hosts=f"http://{os.environ.get('BRON_ARANGO_IP', 'localhost')}:8529")
    sys_db = client.db('_system', username=USER, password=PWD, auth_method="basic")
    if not sys_db.has_user(GUEST):
        sys_db.create_user(username=GUEST, password=GUEST)
        sys_db.update_permission(GUEST, 'ro', DB)
        
    print(sys_db.permissions(GUEST))
    
def arango_import() -> None:
    create_db()
    files = os.listdir()
    edge_keys = [get_edge_collection_name(*_) for _ in get_edge_keys()]
    allowed_names = list(NODE_KEYS) + edge_keys
    for file_ in files:
        name, ext = os.path.splitext(file_)
        if ext == ".json" and name in allowed_names:
            cmd = ["arangoimport", "--collection", name,
                   "--create-collection", "true", "--file", file_, "--type", "jsonl",
                   "--server.password", PWD,
                   "--server.database", DB,
                   "--server.endpoint", f"http+tcp://{os.environ.get('BRON_ARANGO_IP', '127.0.0.1')}:8529",
                   "--server.authentication", "false",
            ]
            if name in edge_keys:
                cmd += ["--create-collection-type", "edge"]

            cmd_str = " ".join(cmd)
            os.system(cmd_str)

            
if __name__ == '__main__':
    bron_file_path = '../example_data/example_output_data/BRON.json'
    #bron_file_path = '../full_data/full_output_data/BRON.json'
    # TODO ip and prot from cli
    parser = argparse.ArgumentParser(description='Create json files to import into ArangoDb from BRON json')
    parser.add_argument("-f", type=str, default=bron_file_path,
                        help="Path to BRON json")
    parser.add_argument("--arango_import", action='store_true', help="Write to arangoimport compatible file. Requires `arangoimport`.")
    parser.add_argument("--create_guest_user", action='store_true', help="Create guest user")
    parser.add_argument("--create_db", action='store_true', help="Create BRON db")
    args = parser.parse_args(sys.argv[1:])
    if args.create_guest_user:
        create_guest_user()
    elif args.create_db:
        create_db()
    elif not args.arango_import:
        main(args.f)
    else:
        arango_import()
