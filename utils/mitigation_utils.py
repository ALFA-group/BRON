import logging
import os
from typing import Any, Dict, List, Optional, Tuple

import arango
import pandas as pd

from graph_db.bron_arango import DB, GRAPH, HOST, get_edge_collection_name


def check_duplicates(df: "pd.DataFrame", keys: List[str]):
    oringal_size = df.shape[0]
    deduplicated_df = df[keys].drop_duplicates()
    deduplicated_size = deduplicated_df.shape[0]
    assert oringal_size == deduplicated_size


def get_collection_names(basename: str) -> Tuple[str]:
    return (f"{basename}_mitigation", f"{basename}_detection")


def get_mitigation_collection_names_wrapper(
    collection_names: Tuple[str],
    name_lookup: Dict[str, Tuple[str, str]],
    bron_data: Dict[str, List[Any]],
    basename: str,
):
    for collection_name in collection_names:
        edge_key = (basename, collection_name)
        lookup, data = get_mitigation_collection_names(collection_name, edge_key)
        name_lookup.update(lookup)
        bron_data.update(data)


def get_mitigation_collection_names(
    collection_name: str, edge_collection_keys: Tuple[str]
) -> Tuple[Dict[str, Tuple[str, str]], Dict[str, List[Any]]]:
    edge_collection_name = get_edge_collection_name(*edge_collection_keys)
    bron_data = {collection_name: [], edge_collection_name: []}
    edge_collection_lookup = {edge_collection_name: edge_collection_keys}
    return edge_collection_lookup, bron_data


def update_BRON_graph_db(
    username: str,
    password: str,
    ip: str,
    bron_data: Dict[str, Any],
    edge_collections: Dict[str, Tuple[str, str]],
    out_dir: str,
) -> None:
    for key in bron_data.keys():
        edge_collection = key in edge_collections.keys()
        name = os.path.join(out_dir, f"import_{key}.jsonl")
        import_into_arango(username, password, ip, name, edge_collection, key)
        if edge_collection:
            update_graph_in_graph_db(
                username, password, ip, edge_key=edge_collections[key]
            )
        else:
            update_graph_in_graph_db(username, password, ip, collection_name=key)


def update_graph_in_graph_db(
    username: str,
    password: str,
    ip: str,
    collection_name: str = "",
    edge_key: Optional[List[str]] = None,
):
    logging.info(f"Update collection_name: {collection_name}; edge_key: {edge_key}")
    host = HOST.format(ip)
    client = arango.ArangoClient(hosts=host)
    db = client.db(DB, username=username, password=password, auth_method="basic")
    assert db.has_graph(GRAPH)
    bron_graph = db.graph(GRAPH)

    # Create vertex collections
    if collection_name:
        if not bron_graph.has_vertex_collection(collection_name):
            _ = bron_graph.vertex_collection(collection_name)
            logging.info(f"Created vertex_collection: {collection_name} to {GRAPH}")

    if edge_key is not None:
        edge_key_collection = get_edge_collection_name(*edge_key)
        if not bron_graph.has_edge_definition(edge_key_collection):
            _ = bron_graph.create_edge_definition(
                edge_collection=edge_key_collection,
                from_vertex_collections=[edge_key[0]],
                to_vertex_collections=[edge_key[1]],
            )
            logging.info(
                f"Created edge_collection: {edge_key_collection} ({edge_key}) to {GRAPH}"
            )

    client.close()


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

    cmd_str = " ".join(cmd)
    os.system(cmd_str)
    logging.info(
        f"Imported {name} from {file_} to {DB} on {ip} (Edge collection = {edge_keys})"
    )


def clean_BRON_mitigation(
    username: str, password: str, ip: str, mitigation_data: Dict[str, Any]
) -> None:
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    db = client.db(DB, username=username, password=password, auth_method="basic")
    for key in mitigation_data.keys():
        db.delete_collection(key)
        logging.info(f"Mitigation deleted {key} from {ip}")

    client.close()


def query_bron(collection, filter_q):
    result = collection.find(filter_q)
    if result.empty():
        logging.warning(f"Empty result for: {filter_q}")
        return None
    if result.count() > 1:
        result = list(result)
        logging.warning(f"Duplicate result for: {result}")

    return result.pop()
