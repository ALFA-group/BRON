import argparse
import collections
import sys
from typing import Any, List, Dict

import arango
from graph_db.bron_arango import GUEST


def find_activities_from_techniques(
    ip: str = "bron.alfa.csail.mit.edu", password: str = GUEST, username: str = GUEST
) -> Dict[str, Any]:
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    db = client.db("BRON", username=username, password=password, auth_method="basic")
    activities = db.collection("engage_activity")
    engage_activities = activities.all()
    print(f"# Engage Activities: {len(engage_activities)}")
    technique_engage_activity_links = db.collection("TechniqueEngage_activity").all()
    techniques = {_["_from"] for _ in technique_engage_activity_links}
    print(
        f"# Technique-EngageActivities: {len(technique_engage_activity_links)}, # Techniques: {len(techniques)}"
    )
    technique_capec_links = set()
    capec_ids = collections.defaultdict(int)
    technique_ids = collections.defaultdict(int)
    for technique in techniques:
        results = db.collection("TechniqueCapec").find({"_from": technique})
        for result in results:
            technique_capec_links.add((result["_from"], result["_to"]))

    print(f"# Technique-CAPEC links: {len(technique_capec_links)}")
    for link in technique_capec_links:
        technique_ids[link[0]] += 1
        capec_ids[link[1]] += 1

    print(f"# CAPEC ids: {len(capec_ids)}\n {capec_ids}")
    print(f"# Technique ids: {len(technique_ids)}\n {technique_ids}")
    client.close()
    return technique_capec_links


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Query Engage and BRON")
    parser.add_argument("--username", type=str, default=GUEST, help="DB username")
    parser.add_argument("--password", type=str, default=GUEST, help="DB password")
    parser.add_argument(
        "--ip", type=str, default="bron.alfa.csail.mit.edu", help="DB IP address"
    )
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
    find_activities_from_techniques(args_.ip, args_.password, args_.username)
    sys.exit()
