from typing import Dict, List, Tuple
import collections
import os
import json
import sys
import argparse
import logging

import arango

from meta_analysis.find_riskiest_software import load_graph_network


logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s', level=logging.INFO)
DB = "BRON"
GRAPH = "BRONGraph"
GUEST = 'guest'
HOST = "http://{}:8529"
NODE_KEYS = ("tactic", "technique", "capec", "cwe", "cve", "cpe")
EDGE_KEYS = (("tactic", "technique"),
             ("technique", "capec"),
             ("capec", "cwe"),
             ("cwe", "cve"),
             ("cve", "cpe"),
             )


def get_edge_keys() -> List[Tuple[str, str]]:
    edge_keys = list(EDGE_KEYS)
    return edge_keys


def create_graph(username: str, password: str, ip: str) -> None:
    host = HOST.format(ip)
    client = arango.ArangoClient(hosts=host)
    db = client.db(DB, username=username, password=password, auth_method="basic")
    
    if not db.has_graph(GRAPH):
        bron_graph = db.create_graph(GRAPH)
    else:
        bron_graph = db.graph(GRAPH)

    edge_keys = get_edge_keys()    
    for edge_key in edge_keys:
        edge_collection_key = get_edge_collection_name(*edge_key)
        if not bron_graph.has_edge_definition(edge_collection_key):
            _ = bron_graph.create_edge_definition(
                edge_collection=edge_collection_key,
                from_vertex_collections=[edge_key[0]],
                to_vertex_collections=[edge_key[1]]
            )
        logging.info(f"Done: {edge_collection_key}")

    
def main(bron_file_path: str, username: str, password: str, ip: str) -> None:
    create_db(username, password, ip)
    create_guest_user(username, password, ip)
    create_graph(username, password, ip)

    edge_keys = get_edge_keys()    
    edge_file_handles = {}
    for edge_key in edge_keys:
        edge_collection_key = get_edge_collection_name(*edge_key)
        edge_file_handles[edge_collection_key] = open(f"{edge_collection_key}.json", "w")
        logging.info(f"Done: {edge_collection_key}")

    
def main(bron_file_path: str) -> None:
    create_db()
    create_graph()

    edge_keys = get_edge_keys()    
    edge_file_handles = {}
    for edge_key in edge_keys:
        edge_collection_key = get_edge_collection_name(*edge_key)
        edge_file_handles[edge_collection_key] = open(f"{edge_collection_key}.json", "w")
        print(f"Done: {edge_collection_key}")

    node_file_handles = {}
    for collection in NODE_KEYS:
        node_file_handles[collection] = open(f"{collection}.json", 'w')        
        logging.info(f"Done: {collection}")
        
    # Load data
    nx_bron_graph = load_graph_network(bron_file_path)
    logging.info("Loaded nx")
    # Insert nodes
    nodes_nx = nx_bron_graph.nodes(data=True)
    for cnt, node in enumerate(nodes_nx):
        document = {"_key": node[0]}
        document.update(node[1])
        node_key = get_node_key(node[0])
        json.dump(document, node_file_handles[node_key])
        node_file_handles[node_key].write("\n")

    _ = [_.close() for _ in node_file_handles.values()]
    logging.info(f"Done: Nodes")

    # Insert edges
    edges_nx = nx_bron_graph.edges()
    for cnt, o_edge in enumerate(edges_nx):
        edge = order_edge(o_edge)
        from_node_key = get_node_key(edge[0])
        from_ = f"{from_node_key}/{edge[0]}"
        to_node_key = get_node_key(edge[1])
        to_ = f"{to_node_key}/{edge[1]}"
        edge_collection_key = get_edge_collection_name(from_node_key, to_node_key)
        document = {'_id': f"{edge_collection_key}/{edge[0]}-{edge[1]}", '_from': from_, '_to':to_}
        json.dump(document, edge_file_handles[edge_collection_key])
        edge_file_handles[edge_collection_key].write("\n")
        
    _ = [_.close() for _ in edge_file_handles.values()]
    logging.info(f"Done: Edges")


def order_edge(edge: Tuple[str, str]) -> Tuple[str, str]:
    if get_edge_type(edge) not in EDGE_KEYS:
        # Reverse
        edge = list(edge)
        edge.reverse()
        edge = tuple(edge)
        assert get_edge_type(edge) in EDGE_KEYS

    return edge


def get_edge_type(edge: Tuple[str, str]) -> Tuple[str, str]:
    return tuple(map(get_node_key, edge))
        
def get_node_key(name: str) -> str:
    return name.split('_')[0]

def get_edge_collection_name(from_collection: str, to_collection: str) -> str:
    return f"{from_collection.capitalize()}{to_collection.capitalize()}"


def create_db(username: str, password: str, ip: str) -> None:
    host = HOST.format(ip)
    client = arango.ArangoClient(hosts=host)
    sys_db = client.db('_system', username=username, password=password, auth_method="basic")
    if not sys_db.has_database(DB):
        sys_db.create_database(DB)

def create_guest_user(username: str, password: str, ip: str) -> None:
    host = HOST.format(ip)
    client = arango.ArangoClient(hosts=host)
    sys_db = client.db('_system', username=username, password=password, auth_method="basic")
    if not sys_db.has_user(GUEST):
        sys_db.create_user(username=GUEST, password=GUEST)

    sys_db.update_permission(GUEST, 'ro', DB)        
    logging.info(sys_db.permissions(GUEST))
    
def arango_import(username: str, password: str, ip: str) -> None:
    create_db(username, password, ip)
    create_graph(username, password, ip)
    files = os.listdir()
    edge_keys = [get_edge_collection_name(*_) for _ in get_edge_keys()]
    allowed_names = list(NODE_KEYS) + edge_keys
    for file_ in files:
        name, ext = os.path.splitext(file_)
        if ext == ".json" and name in allowed_names:
            cmd = ["arangoimport", "--collection", name,
                   "--create-collection", "true", "--file", file_, "--type", "jsonl",
                   "--server.password", password,
                   "--server.database", DB,
                   "--server.endpoint", f"http+tcp://{ip}:8529",
                   "--server.authentication", "false",
            ]
            if name in edge_keys:
                cmd += ["--create-collection-type", "edge"]

            cmd_str = " ".join(cmd)
            # TODO handle overwriting
            os.system(cmd_str)

            
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create json files to import into ArangoDb from BRON json')
    parser.add_argument("-f", type=str,
                        help="Path to BRON.json")
    parser.add_argument("--username", type=str, required=True,
                        help="DB username")
    parser.add_argument("--password", type=str, required=True,
                        help="DB password")
    parser.add_argument("--ip", type=str, required=True,
                        help="DB IP address")
    parser.add_argument("--arango_import", action='store_true', help="Write to arangoimport compatible file. Requires `arangoimport`.")
    parser.add_argument("--create_guest_user", action='store_true', help="Create guest user")
    parser.add_argument("--create_db", action='store_true', help="Create BRON db")
    args = parser.parse_args(sys.argv[1:])
    if args.create_guest_user:
        create_guest_user(args.username, args.password, args.ip)
    elif args.create_db:
        create_db(args.username, args.password, args.ip)
    elif not args.arango_import:
        main(args.f, args.username, args.password, args.ip)
    else:
        arango_import(args.username, args.password, args.ip)
