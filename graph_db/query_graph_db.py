import collections
import sys
from dataclasses import dataclass
from typing import Dict, Any, List, Tuple, Set
import argparse

import arango

from graph_db.bron_arango import DB, USER, PWD, get_edge_keys, get_edge_collection_name, EDGE_KEYS
from path_search.path_search_BRON import get_data


DIRECTIONS = ("INBOUND", "OUTBOUND")


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Analyse network for risk")
    parser.add_argument(
        "--starting_point",
        type=str,
        required=True,
        help="Path to CSV file with Tactic, Technique, CAPEC, CWE, CVE, or CPE data",
    )
    parser.add_argument(
        "--results_file",
        type=str,
        required=True,
        help="Name of file to store results in",
    )
    parser.add_argument(
        "--starting_point_type",
        type=str,
        required=True,
        help="Type of attack argument: one of Tactic, Technique, CAPEC, CVE, CWE, or CPE",
    )
    args = vars(parser.parse_args(args))
    return args


def get_connections(starting_points: List[str], collection_name: str) -> Dict[str, Set["Document"]]:
    connections = collections.defaultdict(set)
    client = arango.ArangoClient(hosts="http://127.0.0.1:8529")
    db = client.db(DB, username=USER, password=PWD, auth_method='basic')
    query_template = """
FOR c IN {}
    FILTER c.original_id == "{}"
    FOR v IN 1..1 {} c {}
        RETURN v
    """
    edge_collections = [get_edge_collection_name(*_) for _ in EDGE_KEYS if collection_name in _]
    assert 1 <= len(edge_collections) <= 2
    for starting_point in starting_points:
        # TODO not getting inbound outbound right...
        for edge_collection in edge_collections:
            for direction in DIRECTIONS:
                query = query_template.format(collection_name, starting_point, direction, edge_collection)
                c = db.collection(collection_name)
                assert db.aql.validate(query)
                cursor = db.aql.execute(query)
                documents = set()
                for document in cursor:
                    d = Document(document['datatype'], document['original_id'], document['name'])
                    documents.add(d)
                connections[starting_point].update(documents)

    print(connections)
    return connections


def get_connection_counts(starting_points: List[str], collection_name: str) -> Dict[str, Dict[str, int]]:
    connections = get_connections(starting_points, collection_name)
    connection_counts = {}
    for key, values in connections.items():
        connection_counts[key] = collections.defaultdict(int)
        for element in values:
            connection_counts[key][element.datatype] += 1

    print(connection_counts)
    return connection_counts


@dataclass(eq=True, frozen=True)
class Document:
    datatype: str
    original_id: str
    name: str


def main(**kwargs: Dict[str, Any]) -> None:
    starting_point_file, results_file, starting_point_type = kwargs.values()
    # Get queries from file
    starting_points = get_data(starting_point_file)
    data = get_connection_counts(starting_points.keys(), starting_point_type)


if __name__ == "__main__":
    kwargs = parse_args(sys.argv[1:])
    main(**kwargs)
