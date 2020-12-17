import collections
import sys
from dataclasses import dataclass
from typing import Dict, Any, List, Set
import argparse

import arango

from graph_db.bron_arango import (
    DB,
    USER,
    PWD,
    get_edge_collection_name,
    EDGE_KEYS,
)
from path_search.path_search_BRON import get_data
from BRON.build_BRON import id_dict_paths


DIRECTIONS = ("INBOUND", "OUTBOUND")
CONNECTIONS_QUERY = """
FOR c IN {}
    FILTER c.original_id == "{}"
    FOR v IN 1..1 {} c {}
        RETURN v
    """


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Analyse network for risk")
    parser.add_argument(
        "--starting_point",
        type=str,
        required=True,
        help="Path to CSV file with Tactic, Technique, CAPEC, CWE, CVE, or CPE data",
    )
    parser.add_argument(
        "--starting_point_type",
        type=str,
        required=True,
        help=f"Data source type is one of: {', '.join(id_dict_paths.keys())}",
    )
    args = vars(parser.parse_args(args))
    assert args['starting_point_type'] in id_dict_paths.keys()
    return args


def get_connections(
    starting_points: List[str], collection_name: str
) -> Dict[str, Set["Document"]]:
    connections = collections.defaultdict(set)
    client = arango.ArangoClient(hosts="http://127.0.0.1:8529")
    db = client.db(DB, username=USER, password=PWD, auth_method="basic")
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
                assert db.aql.validate(query)
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
    starting_points: List[str], collection_name: str
) -> Dict[str, Dict[str, int]]:
    connections = get_connections(starting_points, collection_name)
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


def main(**kwargs: Dict[str, Any]) -> None:
    starting_point_file, starting_point_type = kwargs.values()
    # Get queries from file
    starting_points = get_data(starting_point_file)
    data = get_connection_counts(starting_points.keys(), starting_point_type)
    print(data)

if __name__ == "__main__":
    kwargs = parse_args(sys.argv[1:])
    main(**kwargs)
