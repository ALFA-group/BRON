import json
import argparse
import collections
import sys
from typing import Any, List, Dict, Tuple, Set

import rdflib

from tutorials.threat_reports_with_bron import (
    get_network_matches,
    t_prog,
)
from graph_db.bron_arango import GUEST
from graph_db.query_graph_db import get_connection_counts, get_graph_traversal


D3F_URI = "http://d3fend.mitre.org/ontologies/d3fend.owl"
D3FEND_ONTOLOGY_TTL = "https://d3fend.mitre.org/ontologies/d3fend.ttl"


def main():
    g = rdflib.Graph()
    _ = g.parse(D3FEND_ONTOLOGY_TTL, format="turtle")
    query = """SELECT *
        WHERE {
            ?a rdfs:subClassOf d3f:DigitalArtifact .
            ?b ?c ?a .
        }
        """
    print(query)
    qres = g.query(query)
    for row in qres:
        print(row)


def find_techniques_from_mitigation(artifact: str, g: Any) -> List[str]:
    # TODO get the "object"
    query = """SELECT DISTINCT ?a ?b
        WHERE {{
            ?a ?b d3f:{} .
        }}
        """.format(
        artifact
    )
    qres = g.query(query)
    # TODO filter in SPARQL?
    techniques = []
    for row in qres:
        matches = t_prog.findall(row[0])
        if matches:
            techniques.append(matches[0][0])

    return techniques


def find_artifacts(g: Any) -> List[str]:
    query = """SELECT DISTINCT ?a
        WHERE {
            ?a rdfs:subClassOf d3f:DigitalArtifact ;
        }
        """
    qres = g.query(query)
    artifacts = []
    for row in qres:
        value = str(row[0]).split("#")[-1]
        artifacts.append(value)

    return artifacts


def find_mitigations(g: Any) -> List[str]:
    query = """SELECT DISTINCT ?a ?b
        WHERE {
            ?a d3f:d3fend-id ?b .
        }
        """
    qres = g.query(query)
    # TODO filter in SPARQL?
    mitigations = {}
    for row in qres:
        value = str(row[0]).split("#")[-1]
        key = str(row[1])
        mitigations[key] = value

    return mitigations


def find_mitigation_artifacts(mitigation, artifacts, g) -> List[str]:
    query = """SELECT *
        WHERE {{
            <{}#{}> ?a ?b .
        }}
        """.format(
        D3F_URI, mitigation
    )
    qres = g.query(query)
    related_artifacts = set()
    for row in qres:
        for value in row:
            str_value = str(value)
            if str_value.startswith(D3F_URI):
                artifact = str_value.split("#")[-1]
                if artifact in artifacts:
                    related_artifacts.add(artifact)

    return related_artifacts


def find_mitigation_label(mitigation, g) -> List[str]:
    query = """SELECT *
        WHERE {{
            <{}#{}> rdfs:label ?b .
        }}
        """.format(
        D3F_URI, mitigation
    )
    qres = g.query(query)
    for row in qres:
        label = str(row[0])

    return label


def find_mitigation_comment(mitigation, g) -> List[str]:
    query = """SELECT *
        WHERE {{
            <{}#{}> rdfs:comment ?b .
        }}
        """.format(
        D3F_URI, mitigation
    )
    qres = g.query(query)
    label = ""
    for row in qres:
        label = str(row[0])

    return label


def find_techniques_from_mitigations() -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    g = rdflib.Graph()
    _ = g.parse(D3FEND_ONTOLOGY_TTL, format="turtle")
    mitigations = find_mitigations(g)
    artifacts = find_artifacts(g)
    # TODO why 2 dicts...
    mitigation_technique_map = collections.defaultdict(set)
    technique_mitigation_map = collections.defaultdict(set)
    # TODO SPARQL should be able to do this "join".
    # TODO Try traversing the graph (as in Query 3 https://www.w3.org/2009/Talks/0615-qbe/)
    for mitigtaion_id, mitigation in mitigations.items():
        mitigation_artifacts = find_mitigation_artifacts(mitigation, artifacts, g)
        for artifact in mitigation_artifacts:
            techniques_ = find_techniques_from_mitigation(artifact, g)
            for technique_ in techniques_:
                mitigation_technique_map[mitigation].add(technique_)
                technique_mitigation_map[technique_].add(mitigtaion_id)

    return mitigation_technique_map, technique_mitigation_map


def count_capecs_from_mitigations(
    ip: str = "bron.alfa.csail.mit.edu", password: str = GUEST, username: str = GUEST
) -> Dict[str, Any]:
    _, technique_mitigation_map = find_techniques_from_mitigations()
    records = get_connection_counts(
        technique_mitigation_map.keys(),
        "technique",
        ip=ip,
        password=password,
        username=username,
    )
    mitigation_capecs_map = collections.defaultdict(set)
    for t_key, values in records.items():
        if values.get("capec", 0) > 0:
            m_keys = technique_mitigation_map.get(t_key)
            for m_key in m_keys:
                mitigation_capecs_map[m_key].add(values.get("capec"))

    return mitigation_capecs_map


def find_capecs_from_mitigations_given_network(
    network_description_file: str,
    ip: str = "bron.alfa.csail.mit.edu",
    password: str = GUEST,
    username: str = GUEST,
) -> Dict[str, Any]:
    with open(network_description_file, "r") as fd:
        network_description = json.load(fd)

    _, technique_mitigation_map = find_techniques_from_mitigations()
    print(len(technique_mitigation_map))
    # TODO make these params
    records = get_graph_traversal(
        list(technique_mitigation_map.keys()),
        "technique",
        ip=ip,
        password=password,
        username=username,
    )
    results = {"traversals": {"capec": records}}
    matches = get_network_matches(results, network_description)
    return matches


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Query D3FEND and BRON")
    parser.add_argument("--username", type=str, default=GUEST, help="DB username")
    parser.add_argument("--password", type=str, default=GUEST, help="DB password")
    parser.add_argument("--ip", type=str, default="bron.alfa.csail.mit.edu", help="DB IP address")
    parser.add_argument(
        "--network_description_file",
        type=str,
        default="graph_db/example_data/network_file_bron.json",
        help="DB IP address",
    )
    args = parser.parse_args(args)
    return args


if __name__ == "__main__":
    args_ = parse_args(sys.argv[1:])
    # main()
    matches_ = find_capecs_from_mitigations_given_network(**args_)
    print(matches_)
    sys.exit()
