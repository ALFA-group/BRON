import sys
import argparse

import arango

from meta_analysis.find_riskiest_software import load_graph_network

# Use arango via docker and python-arango package

# TODO have in and out edges? Now only one direction is used

DB = "BRON"
GRAPH = "BRONGraph"
USER = "root"
PWD = "openSesame"
NODE_KEYS = ("tactic", "technique", "capec", "cwe", "cve", "cpe")
EDGE_KEYS = (("tactic", "technique"),
             ("technique", "capec"),
             ("capec", "cwe"),
             ("cwe", "cve"),
             ("cve", "cpe"),
             )

def main(bron_file_path: str) -> None:
    
    adb_client = arango.ArangoClient(hosts=f"http://localhost:8529")
    db = adb_client.db(username=USER, password=PWD)
    if not db.has_database(DB):
        db.create_database(DB)

    db = adb_client.db(DB, username=USER, password=PWD)

    if not db.has_graph(GRAPH):
        bron_graph = db.create_graph(GRAPH)
    else:
        bron_graph = db.graph(GRAPH)

    for edge_key in EDGE_KEYS:
        edge_collection = "-".join(edge_key)
        from_collection = edge_key[0]
        to_collection = edge_key[1]
        if bron_graph.has_edge_definition(edge_collection):
            _ = bron_graph.edge_collection(edge_collection)
        else:
            _ = bron_graph.create_edge_definition(
                edge_collection=edge_collection,
                from_vertex_collections=[from_collection],
                to_vertex_collections=[to_collection]
            )
        print(f"Done: {edge_collection}")

    node_collections = {}
    for collection in NODE_KEYS:
        if not db.has_collection(collection):
            node_collection = db.create_collection(collection) 
        else:
            node_collection = db.collection(collection)
        node_collections[collection] = node_collection
        
        print(f"Done: {collection}")
        
    # Load data
    bron_graph = load_graph_network(bron_file_path)

    for node in bron_graph.nodes(data=True):
        document = {"_key": node[0]}
        document.update(node[1])
        node_key = get_node_key(node[0])
        node_collection = node_collections[node_key]
        try:
            node_collection.insert(document)
        except arango.exceptions.DocumentInsertError:
            pass

    print("Done nodes")
    
    for edge in bron_graph.edges():
        to_node_key = get_node_key(edge[0])
        to_ = f"{to_node_key}/{edge[0]}"
        from_node_key = get_node_key(edge[1])
        from_ = f"{from_node_key}/{edge[1]}"
        edge_collection = f"{to_node_key}-{from_node_key}"
        document = {'_id': f"{edge_collection}/{edge[0]}-{edge[1]}", '_from': from_, '_to':to_}
        try:
            bron_graph.insert_edge(collection=edge_collection, edge=document)
        except arango.exceptions.DocumentInsertError:
            pass

    print("Done edges")
        
def get_node_key(name: str) -> str:
    return name.split('_')[0]


def analyze():
    adb_client = arango.ArangoClient(hosts=f"http://localhost:8529")
    db = adb_client.db(username=USER, password=PWD)
    if not db.has_database(DB):
        db.create_database(DB)

    db = adb_client.db(DB, username=USER, password=PWD)

    bron_graph = db.graph(GRAPH)
    start_vertex = 'tactic/tactic_00002'
    value = bron_graph.traverse(
        start_vertex=start_vertex,
        direction='inbound',
        strategy='bfs',
        edge_uniqueness='global',
        vertex_uniqueness='global',
        min_depth=2,
    )
    print(value)
    
if __name__ == '__main__':
    bron_file_path = './example_data/example_output_data/BRON.json'
    #bron_file_path = './full_data/full_output_data/BRON.json'
    parser = argparse.ArgumentParser(description='Create ArangoDb from BRON json')
    parser.add_argument("-f", type=str, default=bron_file_path,
                        help="Path to BRON json")
    parser.add_argument("--analyse", action='store_true', help="Analyse technique-cve")
    args = parser.parse_args(sys.argv[1:])

    if args.analyse:
        analyze()
    else:
        main(args.f)
