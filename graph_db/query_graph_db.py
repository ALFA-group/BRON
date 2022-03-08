import json
import os
import collections
import sys
from dataclasses import dataclass
from typing import Dict, Any, List, Set
import argparse
import logging

import requests
import arango

from utils.bron_utils import get_csv_data
from graph_db.bron_arango import (
    DB,
    GRAPH,
    get_edge_collection_name,
    EDGE_KEYS,
)
from offense.build_offensive_BRON import ID_DICT_PATHS


DIRECTIONS = ("ANY",)
CONNECTIONS_QUERY = """
FOR c IN {}
    FILTER c.original_id == "{}"
    FOR v IN 1..1 {} c {}
        RETURN v
    """
ID_QUERY = """
FOR c IN {}
    FILTER c.original_id == "{}" OR c.name == "{}"
    RETURN c
"""

TECHNIQUE_NAME_QUERY = """
FOR c IN technique
    FILTER c.original_id=="{}"
    RETURN c._id
"""


def get_technique_id_from_id(_id: str, db: Any) -> str:
    query = TECHNIQUE_NAME_QUERY.format(_id)
    assert db.aql.validate(query), query
    cursor = db.aql.execute(query)
    for document in cursor:
        return document


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Analyse network for risk")
    parser.add_argument(
        "--starting_point",
        type=str,
        required=True,
        help="Path to CSV file with Tactic, Technique, CAPEC, CWE, CVE, or CPE data. E.g. graphd_db/example_data/starting_points_tactics.csv",
    )
    parser.add_argument(
        "--starting_point_type",
        type=str,
        required=True,
        help=f"Data source type is one of: {', '.join(ID_DICT_PATHS.keys())}",
    )
    parser.add_argument("--password", type=str, required=True, help="DB password")
    parser.add_argument("--ip", type=str, required=True, help="DB IP address")
    parser.add_argument("--username", type=str, required=True, help="DB password")
    args = vars(parser.parse_args(args))
    assert args["starting_point_type"] in ID_DICT_PATHS.keys()
    return args


def get_connections(
    starting_points: List[str],
    collection_name: str,
    username: str,
    ip: str,
    password: str,
) -> Dict[str, Set["Document"]]:
    connections = collections.defaultdict(set)
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    db = client.db(DB, username=username, password=password, auth_method="basic")
    edge_collections = [
        get_edge_collection_name(*_) for _ in EDGE_KEYS if collection_name in _
    ]
    assert 1 <= len(edge_collections) <= 2
    for starting_point in starting_points:
        # TODO not getting inbound outbound right... Comes from how data is added to arangodb
        for edge_collection in edge_collections:
            for direction in DIRECTIONS:
                query = CONNECTIONS_QUERY.format(
                    collection_name, starting_point, direction, edge_collection
                )
                assert db.aql.validate(query), query
                cursor = db.aql.execute(query)
                documents = set()
                for document in cursor:
                    d = Document(
                        document["datatype"], document["original_id"], document["name"]
                    )
                    documents.add(d)
                connections[starting_point].update(documents)

    return connections


def get_connection_counts(
    starting_points: List[str],
    collection_name: str,
    username: str,
    ip: str,
    password: str,
) -> Dict[str, Dict[str, int]]:
    connections = get_connections(
        starting_points, collection_name, username, ip, password
    )
    connection_counts = {}
    for key, values in connections.items():
        connection_counts[key] = collections.defaultdict(int)
        for element in values:
            connection_counts[key][element.datatype] += 1

    return connection_counts


@dataclass(eq=True, frozen=True)
class Document:
    datatype: str
    original_id: str
    name: str


def get_graph_traversal(
    starting_points: List[str],
    collection_name: str,
    username: str,
    ip: str,
    password: str,
) -> Dict[str, Dict[str, int]]:
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    db = client.db(DB, username=username, password=password, auth_method="basic")
    graph = db.graph(GRAPH)
    data = {}
    for starting_point in starting_points:
        query = ID_QUERY.format(collection_name, starting_point, starting_point)
        assert db.aql.validate(query), query
        cursor = db.aql.execute(query)
        start_vertex = set()
        for document in cursor:
            start_vertex = document["_id"]

        # TODO Should get only one document
        logging.info(f"{collection_name} {starting_point} {start_vertex}")
        try:
            values = graph.traverse(
                start_vertex=start_vertex,
                direction="ANY",
                strategy="bfs",
                edge_uniqueness="global",
                vertex_uniqueness="global",
                # TODO Max depth number of edges? (More results are
                # provided when it is higher, what does that meann?
                max_depth=len(EDGE_KEYS),
            )
        except TypeError as e:
            logging.error(e)
            logging.error(starting_point)
            values = {}
        except requests.ReadTimeout as e:
            logging.error(e)
            logging.error(starting_point)
            values = {}

        data[starting_point] = values
        logging.info(",".join(map(str, map(len, values.values()))))
        with open(f"tmp_{starting_point}.json", "w") as fd:
            json.dump(values, fd, indent=2)

    # TODO what to return
    return data


def traverse_graph_from_original_id(
    starting_points: List[str],
    collection_name: str,
    username: str,
    ip: str,
    password: str,
) -> Dict[str, Dict[str, int]]:
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    db = client.db(DB, username=username, password=password, auth_method="basic")
    graph = db.graph(GRAPH)
    data = {}
    if collection_name in ("cve",):
        direction = "outbound"
    else:
        direction = "inbound"

    for starting_point in starting_points:
        query = ID_QUERY.format(collection_name, starting_point, starting_point)
        assert db.aql.validate(query), query
        cursor = db.aql.execute(query)
        start_vertex = set()
        for document in cursor:
            start_vertex = document["_id"]

        if not start_vertex:
            logging.info(f"No result for {query}")
            continue

        # TODO Should get only one document
        logging.info(
            f"{collection_name} {starting_point} {start_vertex} for {direction}"
        )
        try:
            # TODO inbound edges and depth, can be costly for CVE
            # TODO make bespoke AQL queries
            values = graph.traverse(
                start_vertex=start_vertex,
                direction=direction,
                strategy="bfs",
                edge_uniqueness="global",
                vertex_uniqueness="global",
                max_depth=len(EDGE_KEYS),
            )
        except TypeError as e:
            logging.error(e)
            logging.error(starting_point)
            values = {}
        except requests.ReadTimeout as e:
            logging.error(e)
            logging.error(starting_point, len(EDGE_KEYS))
            logging.error(query)
            values = {}

        data[starting_point] = values
        logging.info(",".join(map(str, map(len, values.values()))))
        with open(f"tmp_{starting_point}.json", "w") as fd:
            json.dump(values, fd, indent=2)

    client.close()
    # TODO what to return
    return data


def main(**kwargs: Dict[str, Any]) -> None:
    starting_point_file, starting_point_type, password, ip, username = kwargs.values()
    starting_points = get_csv_data(starting_point_file)

    # Traverse graph
    data = get_graph_traversal(
        starting_points.keys(), starting_point_type, username, ip, password
    )

    # Get queries from file
    data = get_connection_counts(
        starting_points.keys(), starting_point_type, username, ip, password
    )
    print(data)


if __name__ == "__main__":
    log_file_name = os.path.split(__file__)[-1].replace(".py", ".log")
    logging.basicConfig(
        filename=f"{log_file_name}",
        format="%(asctime)s %(levelname)s: %(message)s",
        level=logging.INFO,
    )
    kwargs_ = parse_args(sys.argv[1:])
    main(**kwargs_)
