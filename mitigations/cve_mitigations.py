import logging
from collections import defaultdict
from typing import List, Any, Optional, Tuple
import argparse
import os
import sys
import json

import requests
import arango

from graph_db.bron_arango import create_edge_document, get_schemas, validate_entry
from utils import mitigation_utils
from utils.mitigation_utils import query_bron, update_BRON_graph_db, write_jsonl

# Constants
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_OUT_DATA_DIR = "data/mitigations/kev"
KEV_BASENAME = "kev"
KEV_NAME_LOOKUP = {}
KEV_DOWNLOAD_FILE = f"raw_{KEV_BASENAME}.json"
KEV_BRON_DATA = defaultdict(list)


def _create_kev_entry(value: dict, datatype: str, schemas: dict, validation: bool) -> Tuple[dict, str]:
    """Create a KEV entry from vulnerability data."""
    _id = f'KEV-{value["cveID"]}'
    entry = {
        "_key": _id,
        "original_id": str(value["cveID"]),
        "name": value["vulnerabilityName"],
        "metadata": {
            "description": value["shortDescription"],
            "requiredAction": value["requiredAction"],
            "vendorProject": value["vendorProject"],
            "product": value["product"],
        },
        "datatype": datatype,
    }
    
    if validation:
        validate_entry(entry, schemas[datatype])
    
    return entry, _id


def _create_kev_cve_edge(
    cve_bron: Any,
    cve_id: str,
    kev_id: str,
    datatype: str,
    schemas: dict,
    validation: bool,
) -> Optional[dict]:
    """Create an edge between KEV and CVE if the CVE exists in BRON."""
    result = query_bron(cve_bron, {"original_id": cve_id}, warning=False)
    if result is None:
        logging.warning(f"CVE {cve_id} not found in BRON, skipping edge creation")
        return None

    _from = f"{datatype}/{kev_id}"
    _to = result["_id"]
    edge_name = "KevCve"
    return create_edge_document(_from, _to, schemas[edge_name], validation)


def _make_bron_data(
    kev_file_path: str, username: str, password: str, ip: str, validation: bool = True
):
    """Process KEV data and create BRON entries."""
    logging.info(f"Begin KEV for BRON for {ip} from {kev_file_path}")
    
    # Load KEV data
    with open(kev_file_path, "r") as fd:
        data = json.load(fd)

    vulnerabilities = data["vulnerabilities"]
    schemas = get_schemas() if validation else {}
    
    # Connect to database
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    try:
        db = client.db("BRON", username=username, password=password, auth_method="basic")
        cve_bron = db.collection("cve")
        
        # Process each vulnerability
        for value in vulnerabilities:
            datatype = "kev"
            entry, kev_id = _create_kev_entry(value, datatype, schemas, validation)
            KEV_BRON_DATA[datatype].append(entry)
            
            # Create edge to CVE if it exists
            edge = _create_kev_cve_edge(
                cve_bron, str(value["cveID"]), kev_id, datatype, schemas, validation
            )
            if edge:
                KEV_BRON_DATA["KevCve"].append(edge)
    finally:
        client.close()

    # Write output files
    for key, value in KEV_BRON_DATA.items():
        file_path = os.path.join(KEV_OUT_DATA_DIR, f"import_{key}.jsonl")
        write_jsonl(file_path, value)


def update_BRON_graph_db(username: str, password: str, ip: str):
    mitigation_utils.update_BRON_graph_db(
        username,
        password,
        ip,
        KEV_BRON_DATA,
        KEV_NAME_LOOKUP,
        KEV_OUT_DATA_DIR,
    )


def _download_kev(file_path: str):
    """Download KEV data from CISA."""
    logging.info(f"Downloading KEV data from {KEV_URL}")
    response = requests.get(KEV_URL)
    response.raise_for_status()
    
    with open(file_path, "w") as fd:
        json.dump(response.json(), fd, indent=2)

    logging.info(f"Stored: {file_path}")


def clean_BRON_kev(username: str, password: str, ip: str) -> None:
    """Clean KEV-related collections from BRON database."""
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    try:
        db = client.db("BRON", username=username, password=password, auth_method="basic")
        for collection in db.collections():
            collection_name = collection["name"]
            if "kev" in collection_name.lower() or "Engage" in collection_name:
                db.delete_collection(collection_name)
                logging.info(f"DELETED {collection_name}")
    finally:
        client.close()


def main(
    kev_file_path: str,
    username: str,
    password: str,
    ip: str,
    validation: bool = True,
    no_download: bool = False,
):
    """Main function to process KEV data."""
    os.makedirs(KEV_OUT_DATA_DIR, exist_ok=True)
    if not no_download:
        _download_kev(kev_file_path)
    _make_bron_data(kev_file_path, username, password, ip, validation)


def parse_args(args: List[str]) -> Any:
    parser = argparse.ArgumentParser(description="Link KEV mitigations to BRON")
    parser.add_argument("--username", type=str, required=True, help="DB username")
    parser.add_argument("--password", type=str, required=True, help="DB password")
    parser.add_argument("--ip", type=str, required=True, help="DB IP address")
    parser.add_argument("--no_download", action="store_true", help="Do not download data")
    parser.add_argument(
        "--arango_import",
        action="store_true",
        help="Create files and use arangoimport with created json files. Requires `arangoimport`.",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Delete KEV and Engage related collections.",
    )
    args = parser.parse_args(args)
    return args


if __name__ == "__main__":
    log_file = os.path.basename(__file__).replace(".py", ".log")
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s",
        level=logging.INFO,
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )

    args_ = parse_args(sys.argv[1:])
    if args_.clean:
        clean_BRON_kev(args_.username, args_.password, args_.ip)

    if args_.arango_import:
        update_BRON_graph_db(args_.username, args_.password, args_.ip)
    else:
        file_path = os.path.join(KEV_OUT_DATA_DIR, KEV_DOWNLOAD_FILE)
        main(
            file_path,
            username=args_.username,
            password=args_.password,
            ip=args_.ip,
            no_download=args_.no_download,
        )
