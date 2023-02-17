import collections
import os
import json
import argparse
import sys
import re
import logging
from typing import Dict, Set, List, Any

import requests
from pdfminer.high_level import extract_text
from bs4 import BeautifulSoup

from graph_db.query_graph_db import get_connection_counts, get_graph_traversal
from offense.build_offensive_BRON import ID_DICT_PATHS


REPORT_URL = "https://media.defense.gov/2020/Dec/17/2002554125/-1/-1/0/AUTHENTICATION_MECHANISMS_CSA_U_OO_198854_20.PDF"
MDR_URL = "https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/"
# TODO get 403 for MDR_HTML so it is amnually downloaded...
MDR_HTM = "graph_db/example_data/mdr_solarigate.htm"
FIRE_EYE_URL = (
    "https://github.com/fireeye/red_team_tool_countermeasures/blob/master/CVEs_red_team_tools.md"
)
# TODO all in one regex
ta_re_pattern = "TA00\d{2}"
ta_prog = re.compile(ta_re_pattern)
t_re_pattern = "(T\d{4}(\.\d{3})?)"
t_prog = re.compile(t_re_pattern)
cve_re_pattern = "CVE-\d{4}-\d{4,7}"
cve_prog = re.compile(cve_re_pattern)


def get_report(url: str) -> Dict[str, Set[str]]:
    response = requests.get(url, timeout=5)
    # TODO use tmpfile module
    tmp_file_path = "/tmp/metadata.pdf"
    result = {}
    text = ""
    if "pdf" in response.headers["Content-Type"]:
        with open(tmp_file_path, "wb") as f:
            f.write(response.content)
            text = extract_text(tmp_file_path)
            # Parse data types from report
            # TODO pares more info?
    elif response.status_code == 403:
        # TODO hack. Manually downloaded webpge
        with open(MDR_HTM, "r") as fd:
            soup = BeautifulSoup(fd.read(), "lxml")
            text = soup.get_text()
    else:
        html_text = response.text
        soup = BeautifulSoup(html_text, "html.parser")
        text = soup.get_text()

    result["tactic"] = set(ta_prog.findall(text))
    result["technique"] = set([_[0] for _ in t_prog.findall(text)])
    result["cve"] = set(cve_prog.findall(text))

    return result


# Query bron with info
def get_queries(
    all_starting_points: Dict[str, List[str]], ip: str, password: str, username: str
) -> Dict[str, Any]:
    results = {"records": {}, "traversals": {}}
    for datatype, starting_points in all_starting_points.items():
        assert datatype in ID_DICT_PATHS
        logging.info(f"Query {datatype}")
        records = get_connection_counts(starting_points, datatype, username, ip, password)
        results["records"][datatype] = records
        traversals = get_graph_traversal(starting_points, datatype, username, ip, password)
        results["traversals"][datatype] = traversals

    print(f"Query results records: {json.dumps(results['records'], indent=1)}")
    n_traversals = dict([(_, len(_)) for _ in results["traversals"]])
    print(f"Query results number of traversals: {json.dumps(n_traversals, indent=1)}")
    return results


# Query bron with network for report
def get_network_matches(
    results: Dict[str, Any], network_description: Dict[str, Any]
) -> Dict[str, Any]:
    # TODO filter queries in Arango? (Is it faster?)
    # TODO use edges
    traversals = results["traversals"]
    cpes = set()
    for values in network_description["nodes"].values():
        cpes.add(values["os"])
        for app in values["apps"]:
            cpes.add(app)

    print(f"Number of configurations in CPE format in network {len(cpes)}")
    matches = collections.defaultdict(set)
    for key, starting_point in traversals.items():
        for node, values in starting_point.items():
            logging.info(f"Match {key} {node}")
            verticies = values.get("vertices", [])
            for vertex in verticies:
                if vertex["datatype"] == "cpe":
                    # TODO more matches
                    # Exact matches
                    if vertex["original_id"] in cpes:
                        matches[key].add(node)

    matches = dict([(k, list(v)) for k, v in matches.items()])
    print(f"Network matches: {json.dumps(matches, indent=1)}")

    return matches


# TODO

# - Docker file

# - Get the other attack data and link: intrusion set(groups), realtions, malware, coa, tool

# - BRON display names and metadata


def main(
    ip: str,
    password: str,
    username: str,
    url: str,
    network_description_file: str = "",
    save_folder: str = "",
    load_folder: str = "",
) -> Dict[str, Any]:
    if load_folder != "":
        results = {}
        for _file in os.listdir(load_folder):
            if _file.endswith("query_bron.json"):
                with open(os.path.join(load_folder, _file), "r") as fd:
                    data = json.load(fd)
                    results.update(data)

    else:
        data = get_report(url)
        data = dict((k, list(v)) for k, v in data.items())
        results = get_queries(data, ip, password, username)

    if save_folder != "":
        # TODO save earlier to reduce memory use
        os.makedirs(save_folder, exist_ok=True)
        for key, value in results.items():
            save_file = os.path.join(save_folder, f"{key}_query_bron.json")
            with open(save_file, "w") as fd:
                json.dump({key: value}, fd, indent=2)

    if network_description_file != "":
        with open(network_description_file, "r") as fd:
            network_description = json.load(fd)

        results = get_network_matches(results, network_description)

    return results


if __name__ == "__main__":
    log_file_name = os.path.split(__file__)[-1].replace(".py", ".log")
    logging.basicConfig(
        filename=f"{log_file_name}",
        format="%(asctime)s %(levelname)s: %(message)s",
        level=logging.INFO,
    )

    parser = argparse.ArgumentParser(description="BRON ArangoDB Example")
    parser.add_argument("--username", type=str, required=True, help="DB username. E.g. guest")
    parser.add_argument("--password", type=str, required=True, help="DB password. E.g. guest")
    parser.add_argument(
        "--ip",
        type=str,
        required=True,
        help="DB IP address. E.g. bron.alfa.csail.mit.edu",
    )
    parser.add_argument("--url", type=str, default="", help="URL to parse and pass through BRON")
    parser.add_argument(
        "--network_description_file",
        type=str,
        default="",
        help="Path to network description. Currently a json with 'nodes' and 'edges'. E.g. graph_db/example_data/network_file_bron.json",
    )
    parser.add_argument("--save_folder", type=str, default="", help="Save results in folder")
    parser.add_argument(
        "--load_folder",
        type=str,
        default="",
        help="Load results from folder. Will not do any queries.",
    )
    args = parser.parse_args(sys.argv[1:])
    _ = main(**vars(args))
