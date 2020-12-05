import arango

from meta_analysis.find_riskiest_software import load_graph_network

# Use arango via docker and python-arango package

# TODO have class/collection for each data type?

DB = "BRON"
GRAPH = "BRONGraph"
COLLECTION = "Nodes"
EDGE_COLLECTION = "Edges"
USER = "root"
PWD = "openSesame"

def main(bron_file_path: str) -> None:
    
    adb_client = arango.ArangoClient(hosts=f"http://localhost:8529")
    # Connect to "test" database as root user.
    db = adb_client.db(username=USER, password=PWD)
    if not db.has_database(DB):
        db.create_database(DB)

    db = adb_client.db(DB, username=USER, password=PWD)

    if not db.has_graph(GRAPH):
        BRONGraph = db.create_graph(GRAPH)
    else:
        BRONGraph = db.graph(GRAPH)

    if BRONGraph.has_edge_definition(EDGE_COLLECTION):
        edge_collection = BRONGraph.edge_collection(EDGE_COLLECTION)
    else:
        edge_collection = BRONGraph.create_edge_definition(
            edge_collection=EDGE_COLLECTION,
            from_vertex_collections=[COLLECTION],
            to_vertex_collections=[COLLECTION]
        )
        
    if not db.has_collection(COLLECTION):
        nodes_collection = db.create_collection(COLLECTION) 
    else:
        nodes_collection = db.collection(COLLECTION)

    print("Collection/Graph Setup done.")


    # Load data
    bron_graph = load_graph_network(bron_file_path)

    for node in bron_graph.nodes(data=True):
        document = {"_key": node[0]}
        document.update(node[1])
        try:
            nodes_collection.insert(document)
        except arango.exceptions.DocumentInsertError:
            pass

    for edge in bron_graph.edges():
        for i in range(2):
            to_ = f"{COLLECTION}/{edge[i]}"
            from_ = f"{COLLECTION}/{edge[(i + 1) % 2]}"
            document = {'_id': f"{EDGE_COLLECTION}/{edge[i]}-{edge[(i + 1) % 2]}", '_from': from_, '_to':to_}
            try:
                BRONGraph.insert_edge(collection=EDGE_COLLECTION, edge=document)
            except arango.exceptions.DocumentInsertError:
                pass

    

if __name__ == '__main__':
    #bron_file_path = './example_data/example_output_data/BRON.json'
    bron_file_path = './full_data/full_output_data/BRON.json'
    main(bron_file_path)
