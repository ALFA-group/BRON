from hashlib import md5
import re
import subprocess
from typing import Dict, List, Optional, Tuple, Any
import os
import json
import sys
import argparse
import logging
import uuid

import arango
from arango.http import DefaultHTTPClient
import jsonschema
from tqdm import tqdm

from utils.bron_utils import load_graph_network


DB = "BRON"
GRAPH = "BRONGraph"
GUEST = "guest"
HOST = "http://{}:8529"
NODE_KEYS = ("tactic", "technique", "capec", "cwe", "cve", "cpe")
EDGE_KEYS = (
    ("tactic", "technique"),
    ("technique", "capec"),
    ("capec", "cwe"),
    ("cwe", "cve"),
    ("cve", "cpe"),
)
SCHEMA_FOLER = "graph_db/schemas"
DOWNLOAD_PATH = "data/BRON_collection_downloads"


class NoTimeoutHttpClient(DefaultHTTPClient):
    """Extend the default arango http client, to remove timeouts for bulk data."""

    REQUEST_TIMEOUT = None


def get_edge_keys() -> List[Tuple[str, str]]:
    edge_keys = list(EDGE_KEYS)
    return edge_keys


def create_graph(
    username: str,
    password: str,
    ip: str,
    node_keys: Tuple[str],
    edge_keys: List[Tuple[str, str]],
) -> None:
    host = HOST.format(ip)
    client = arango.ArangoClient(hosts=host)
    db = client.db(DB, username=username, password=password, auth_method="basic")

    if not db.has_graph(GRAPH):
        bron_graph = db.create_graph(GRAPH)
    else:
        bron_graph = db.graph(GRAPH)

    # Create vertex collections
    for vertex in node_keys:
        if not bron_graph.has_vertex_collection(vertex):
            _ = bron_graph.vertex_collection(vertex)
            logging.info(f"Created vertex_collection: {vertex}")

    for edge_key in edge_keys:
        edge_collection_key = get_edge_collection_name(*edge_key)
        if not bron_graph.has_edge_definition(edge_collection_key):
            _ = bron_graph.create_edge_definition(
                edge_collection=edge_collection_key,
                from_vertex_collections=[edge_key[0]],
                to_vertex_collections=[edge_key[1]],
            )
            logging.info(f"Created edge_collection: {edge_collection_key}")

    client.close()


def get_edge_key(edge: str) -> str:
    # TODO compile regexp patterns
    if re.match("CA-\\d{1,3}", edge):
        return "capec"
    elif edge.startswith("cpe:2"):
        return "cpe"
    elif edge.startswith("CVE"):
        return "cve"
    elif re.match("CWE-\\d{1,4}", edge):
        return "cwe"
    elif re.match("G\\d{4}", edge):
        return "group"
    elif re.match("S\\d{4}", edge):
        return "software"
    elif re.match("TA\\d{4}", edge):
        return "tactic"
    elif re.match("T\\d{4}(\\.\\d{3})?", edge):
        return "technique"
    else:
        raise KeyError(edge)


def main(
    bron_file_path: str, username: str, password: str, ip: str, validation: bool = False
) -> None:
    create_db(username, password, ip)
    create_guest_user(username, password, ip)
    create_graph(username, password, ip, NODE_KEYS, get_edge_keys())

    edge_keys = get_edge_keys()
    edge_files = []
    edge_file_handles = {}
    for edge_key in edge_keys:
        edge_collection_key = get_edge_collection_name(*edge_key)
        edge_file_handles[edge_collection_key] = open(f"{edge_collection_key}.json", "w")
        edge_files.append(f"{edge_collection_key}.json")
        logging.info(f"Done: {edge_collection_key}")

    node_file_handles = {}
    for collection in NODE_KEYS:
        node_file_handles[collection] = open(f"{collection}.json", "w")
        logging.info(f"Done: {collection}")

    # Load data
    nx_bron_graph = load_graph_network(bron_file_path)
    logging.info("Loaded nx")
    if validation:
        schemas = get_schemas()

    # TODO seems like there could be speed ups from handling I/O better here...
    # Insert nodes
    nodes_nx = nx_bron_graph.nodes(data=True)
    logging.info(f"Begin {len(nodes_nx)} nodes. Validation is {validation}")
    for _, node in enumerate(tqdm(nodes_nx)):
        document = {"_key": node[0]}
        document.update(node[1])
        if validation:
            try:
                validate_entry(document, schemas[node[1]["datatype"]])
            except KeyError as e:
                logging.error(e)
                logging.error(f"{node}, {_}")
                continue
            
        node_key = get_node_key(node[1]["datatype"])
        json.dump(document, node_file_handles[node_key])
        node_file_handles[node_key].write("\n")

    _ = [_.close() for _ in node_file_handles.values()]
    logging.info(f"Done: Nodes fo file")

    # Insert edges
    edges_nx = nx_bron_graph.edges()
    logging.info(f"Begin {len(edges_nx)} edges. Validation is {validation}")
    for _, o_edge in enumerate(tqdm(edges_nx)):        
        try:
            document, edge_collection_key = get_edge_document(o_edge, validation, schemas)
        except KeyError as e:
            # TODO hacky to handle with exception
            edge = order_edge(o_edge)
            document, edge_collection_key  = get_edge_document(edge, validation, schemas)
            
        json.dump(document, edge_file_handles[edge_collection_key])        
        edge_file_handles[edge_collection_key].write("\n")        

    _ = [_.close() for _ in edge_file_handles.values()]
    for file_name in edge_files:        
        assert os.path.getsize(file_name) > 0
        
    logging.info(f"Done: Edges to file")


def get_edge_document(o_edge: Tuple[str, str], validation: bool, schemas: dict[str, Any]) -> Tuple[Dict[str, str], str]:
    edge = order_edge(o_edge)
    from_node_key = get_edge_key(edge[1])
    from_ = f"{from_node_key}/{edge[1]}"
    to_node_key = get_edge_key(edge[0])
    to_ = f"{to_node_key}/{edge[0]}"
    edge_collection_key = get_edge_collection_name(from_node_key, to_node_key)

    document = create_edge_document(from_, to_, schemas[edge_collection_key], validation)
    return document, edge_collection_key        
    

def create_edge_document(from_: str, to_: str, schema: str, validation: bool) -> Dict[str, str]:
    name_str = f"{from_}-{to_}"
    db_key = md5(name_str.encode("utf-8")).hexdigest()
    document = {
        "_key": db_key,
        "_from": from_,
        "_to": to_,
    }
    if validation:
        validate_entry(document, schema)
        
    #logging.info(document)
    return document
    
def order_edge(edge: Tuple[str, str]) -> Tuple[str, str]:
    if get_edge_type(edge) not in EDGE_KEYS:
        # Reverse
        edge = list(edge)
        edge.reverse()
        edge = tuple(edge)

    return edge


def get_edge_type(edge: Tuple[str, str]) -> Tuple[str, str]:
    return tuple(map(get_node_key, edge))


def get_node_key(name: str) -> str:
    return name.split("_")[0]


def get_edge_collection_name(from_collection: str, to_collection: str) -> str:
    name = f"{from_collection.capitalize()}{to_collection.capitalize()}"
    return name


def create_db(username: str, password: str, ip: str) -> None:
    host = HOST.format(ip)
    client = arango.ArangoClient(hosts=host)
    sys_db = client.db("_system", username=username, password=password, auth_method="basic")
    if not sys_db.has_database(DB):
        sys_db.create_database(DB)
        logging.info(f"Created {DB} at {host}")

    client.close()


def create_guest_user(username: str, password: str, ip: str) -> None:
    host = HOST.format(ip)
    client = arango.ArangoClient(hosts=host)
    sys_db = client.db("_system", username=username, password=password, auth_method="basic")
    if not sys_db.has_user(GUEST):
        sys_db.create_user(username=GUEST, password=GUEST)
        logging.info(f"Created user {GUEST} at {HOST} in {DB}")

    sys_db.update_permission(GUEST, "ro", DB)
    logging.info(sys_db.permissions(GUEST))
    client.close()


def log_arangoimport_output(stdout: str, stderr: str, file_name: str, collection_name: str):
    lines = stdout.split('\n')
    keys = ('created', 'updated', 'ignored')        
    for line in lines:        
        values = [_.strip() for _ in line.split(':')]
        key = values[0]
        if len(values) == 2:
            value = values[1]
            if key == 'warnings':
                logging.warning(f"{value} {key} for {collection_name} from {file_name}")
            elif key == 'errors':
                logging.error(f"{value} {key} for {collection_name} from {file_name}")
            elif key in keys:
                logging.info(f"{value} {key} for {collection_name} from {file_name}")

    if stderr:
        logging.error(f"{file_name} {stderr}")
        
        
def import_into_arango(
    username: str,
    password: str,
    ip: str,
    file_: str,
    edge_keys: bool,
    name: str,
) -> None:
    cmd = [
        "arangoimport",
        "--collection",
        name,
        "--create-collection",
        "true",
        "--file",
        file_,
        "--type",
        "jsonl",
        "--server.password",
        password,
        "--server.database",
        DB,
        "--server.endpoint",
        f"http+tcp://{ip}:8529",
        "--server.authentication",
        "false",
        "--on-duplicate",
        "ignore",
    ]
    if edge_keys:
        cmd += ["--create-collection-type", "edge"]

    client = get_bron_db(username, password, ip)
    db = client.db(DB, username, password, auth_method="basic")
    if name in db.collections():
        logging.info(f"Existing {DB} on {ip} collection {name} count {collection.count()}")
            
    process = subprocess.run(cmd, capture_output=True, check=True, text=True)
    log_arangoimport_output(str(process.stdout), str(process.stderr), file_, name)
    
    collection = db.collection(name)
    client.close()
    assert collection.count() > 0
    logging.info(f"Imported {name} from {file_} to {DB} on {ip} collection {name} count {collection.count()}")


def arango_import(username: str, password: str, ip: str) -> None:
    create_db(username, password, ip)
    create_graph(username, password, ip, NODE_KEYS, get_edge_keys())
    files = os.listdir()
    edge_keys = [get_edge_collection_name(*_) for _ in get_edge_keys()]
    allowed_names = list(NODE_KEYS) + edge_keys
    for file_ in files:
        name, ext = os.path.splitext(file_)
        if ext == ".json" and name in allowed_names:
            import_into_arango(username, password, ip, file_, edge_keys, name)
            

def network_import(network_import_file: str, username: str, password: str, ip: str) -> None:
    # TODO what is a good network file format... Now it is home made...
    with open(network_import_file, "r") as fd:
        network = json.load(fd)

    print(network)
    # TODO implement


def get_schemas() -> Dict[str, Dict[str, Any]]:
    logging.info(f"Begin reading schemas from {SCHEMA_FOLER}")
    schemas = {}
    _files = os.listdir(SCHEMA_FOLER)
    for _file in _files:
        if not _file.endswith("_schema.json"):
            continue
        file_path = os.path.join(SCHEMA_FOLER, _file)
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        schemas[schema["title"]] = schema

    # TODO why not os.walk?
    folder_ = os.path.join(SCHEMA_FOLER, "edge_collections")
    _files = os.listdir(folder_)
    for _file in _files:
        if not _file.endswith("_schema.json"):
            continue
        file_path = os.path.join(folder_, _file)
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        schemas[schema["title"]] = schema

    logging.info(f"Done returning {len(schemas)} schemas")
    return schemas


def get_schema(collection: str) -> Optional[Dict[str, Any]]:
    logging.info(f"Begin reading schema for {collection} from {SCHEMA_FOLER}")
    for (root, _, files) in os.walk(SCHEMA_FOLER):
        for _file in files:
            if _file == f"{collection}_schema.json":
                file_path = os.path.join(root, _file)
                with open(file_path, "r") as fd:
                    schema = json.load(fd)
                    logging.info(f"Done found schema at {file_path}")
                    return schema

    return None


def validate_entry(entry: Dict[str, Any], schema: Dict[str, Any]) -> None:
    try:
        jsonschema.validate(instance=entry, schema=schema)
    except jsonschema.exceptions.ValidationError as err:
        logging.error(f"Invalid json for {entry} for schema {schema['title']}. Error:\n{err}")
        raise jsonschema.exceptions.ValidationError(err)


def download_collections_wrapper(username: str, password: str, ip: str, **kwargs) -> None:
    logging.info(f"Begin download all collections")
    with open("graph_db/schema.json", "r") as fd:
        schema = json.load(fd)

    _collections = []
    for collections in schema.values():
        _collections.extend(collections)

    download_collections(username, password, ip, _collections)
    logging.info(f"Done download all collections")


def download_collections(
    username: str,
    password: str,
    ip: str,
    collections: List[str],
    download_path: str = DOWNLOAD_PATH,
) -> None:
    logging.info(
        f"Begin download collections {collections} to {download_path} for {username} from {ip}"
    )
    os.makedirs(download_path, exist_ok=True)
    logging.info(f"Begin downlaod from {ip}")
    for collection_name in tqdm(collections):
        cmd = [
            "arangoexport",
            "--collection",
            collection_name,
            "--type",
            "jsonl",
            "--output-directory",
            download_path,
            "--server.password",
            password,
            "--server.database",
            DB,
            "--server.endpoint",
            f"http+tcp://{ip}:8529",
            "--server.authentication",
            "false",
            "--overwrite",
            "true",
        ]
        subprocess.run(cmd)
        assert os.path.exists(os.path.join(download_path, f"{collection_name}.jsonl"))

    logging.info(f"End download from {ip} to {download_path}")


def get_bron_db(
    username: str,
    password: str,
    ip: str,
) -> "arango.Client":
    logging.info(f"Get {DB} from {ip} for {username}")
    client = arango.ArangoClient(hosts=f"http://{ip}:8529", http_client=NoTimeoutHttpClient())
    return client


if __name__ == "__main__":
    log_file = os.path.basename(__file__).replace(".py", ".log")
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s",
        level=logging.INFO,
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )

    parser = argparse.ArgumentParser(
        description="Create json files to import into ArangoDb from BRON json"
    )
    parser.add_argument("-f", type=str, help="Path to BRON.json")
    parser.add_argument("--username", type=str, required=True, help="DB username")
    parser.add_argument("--password", type=str, required=True, help="DB password")
    parser.add_argument("--ip", type=str, required=True, help="DB IP address")
    parser.add_argument(
        "--arango_import",
        action="store_true",
        help="Use arangoimport with created json files from BRON. Requires `arangoimport`.",
    )
    parser.add_argument(
        "--network_import", type=str, default="", help="Import a network description."
    )
    parser.add_argument("--create_guest_user", action="store_true", help="Create guest user")
    parser.add_argument("--create_db", action="store_true", help="Create BRON db")
    parser.add_argument("--download", action="store_true", help="Download BRON db")
    parser.add_argument(
        "--same_datasource_links",
        action="store_true",
        help="Create edges between same datasources",
    )
    args = parser.parse_args(sys.argv[1:])
    if args.create_guest_user:
        create_guest_user(args.username, args.password, args.ip)
    elif args.network_import != "":
        network_import(args.network_import, args.username, args.password, args.ip)
    elif args.create_db:
        create_db(args.username, args.password, args.ip)
    elif args.download:
        download_collections_wrapper(args.username, args.password, args.ip)
    elif not args.arango_import:
        main(args.f, args.username, args.password, args.ip)
    elif args.same_datasource_links:
        create_db(args.username, args.password, args.ip)
    else:
        arango_import(args.username, args.password, args.ip)
