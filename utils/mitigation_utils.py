import collections
import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple, Set

import arango
import pandas as pd
from tqdm import tqdm

from graph_db.bron_arango import (
    DB,
    GRAPH,
    HOST,
    create_edge_document,
    get_edge_collection_name,
    get_schema,
    import_into_arango,
    validate_entry,
)


def check_duplicates(df: "pd.DataFrame", keys: List[str]):
    original_size = df.shape[1]
    deduplicated_df = df.drop_duplicates(subset=keys)
    deduplicated_size = deduplicated_df.shape[1]
    assert original_size == deduplicated_size, f"{original_size} != {deduplicated_size}"
    return deduplicated_df


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
            update_graph_in_graph_db(username, password, ip, edge_key=edge_collections[key])
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
            logging.info(f"Created edge_collection: {edge_key_collection} ({edge_key}) to {GRAPH}")

    client.close()


def clean_BRON_mitigation(
    username: str, password: str, ip: str, mitigation_data: Dict[str, Any]
) -> None:
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    db = client.db(DB, username=username, password=password, auth_method="basic")
    for key in mitigation_data.keys():
        db.delete_collection(key)
        logging.info(f"Mitigation deleted {key} from {ip}")

    client.close()


def clean_BRON_collections(username: str, password: str, ip: str, collections: Set[str]) -> None:
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    db = client.db(DB, username=username, password=password, auth_method="basic")
    for key in collections:
        if db.has_collection(key):
            db.delete_collection(key)
            logging.info(f"Collection deleted {key} from {ip}")

    client.close()


def query_bron(collection, filter_q, warning=True):
    result = collection.find(filter_q)
    if result.empty():
        if warning:
            logging.warning(f"Empty result for: {filter_q}")
            
        return None
    if result.count() > 1:
        result = list(result)
        logging.warning(f"Duplicate result for: {result}")

    return result.pop()


def query_bron_aql(collection_name: str, filter_q: str, db) -> Optional[Dict[str, str]]:
    query = f"""
    FOR c in {collection_name}
        FILTER c.original_id == "{filter_q}"
        RETURN c
    """
    assert db.aql.validate(query)
    cursor = db.aql.execute(query)
    result = [c for c in cursor]
    if not result:
        logging.warning(f"Empty result for: {filter_q}")
        return None
    if len(result) > 1:
        logging.warning(f"Duplicate result for: {result}")

    return result[0]


def write_jsonl(file_path: str, data: List[Any]):
    with open(file_path, "w") as fd:
        for item in data:
            fd.write(json.dumps(item))
            fd.write("\n")

    logging.info(f"Wrote {len(data)} to file {file_path}")


def read_jsonl(file_path: str) -> List[Any]:
    data = []
    with open(file_path, "r") as fd:
        for line in fd:
            data.append(json.loads(line))

    logging.info(f"Read {len(data)} from file {file_path}")
    return data


# TODO refactor to use this more?
def link_data(
    db,
    file_path: str,
    edge_name: str,
    dst: str,
    validation: bool,
    id_map: Dict[str, str],
    collection_name,
    basename: str,
    data: Dict[str, List[Dict[str, str]]],
    id_key: str,
):
    logging.info(f"Linking {file_path} data for {edge_name} with {dst}.")
    df = pd.read_json(file_path, lines=True)
    if validation:
        schema = get_schema(edge_name)

    collection_ = db.collection(collection_name)
    errors = collections.defaultdict(int)
    query_miss = collections.defaultdict(int)
    for i in tqdm(range(len(df))):
        value = df.loc[i]
        result = query_bron(collection_, {"original_id": str(value[dst])})

        if result is None:
            query_miss[str(value[dst])]
            continue

        _id = value[id_key]
        try:
            _from = f"{basename}/{id_map[_id]}"
        except KeyError as e:
            errors[str(e)] += 1
            continue

        _to = result["_id"]
        document = create_edge_document(_from, _to, schema, validation)        
        data[edge_name].append(document)

    logging.info(f"Errors for {len(errors)} ids {sum(errors.values())} times")
    logging.info(
        f"Query misses for {len(query_miss)} ids {sum(query_miss.values())} times"
    )
    logging.info(f"Done Linking for {collection_.name}")