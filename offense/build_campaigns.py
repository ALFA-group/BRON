import sys
import argparse
import os
from typing import List, Any, Dict
import arango
import logging
from collections import defaultdict

import pandas as pd
from tqdm import tqdm

from utils.mitigation_utils import (
    check_duplicates,
    update_BRON_graph_db,
    query_bron,
    clean_BRON_collections,
    write_jsonl,
)
from graph_db.bron_arango import create_edge_document, get_schema, get_schemas, validate_entry


# Constants
CAMPAIGNS_OUT_DATA_DIR = "data/attacks"
CAMPAIGNS_BASENAME = "campaign"
CAMPAIGNS_EDGE_COLLECTION_NAMES = {
    "CampaignTechnique": (CAMPAIGNS_BASENAME, "technique"),
    "CampaignSoftware": (CAMPAIGNS_BASENAME, "software"),
    "CampaignGroup": (CAMPAIGNS_BASENAME, "group"),
}
CAMPAIGNS_BRON_DATA = defaultdict(list)


def build_campaign(
    save_path: str,
    username: str,
    password: str,
    ip: str,
    validation: bool = True,
    update_bron_graphdb: bool = True,
):
    """Build campaign entries in BRON database."""
    os.makedirs(CAMPAIGNS_OUT_DATA_DIR, exist_ok=True)
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    try:
        _build_campaign(save_path, username, password, ip, client, validation)
    finally:
        client.close()
    
    if update_bron_graphdb:
        update_BRON_graph_db(
            username,
            password,
            ip,
            CAMPAIGNS_BRON_DATA,
            CAMPAIGNS_EDGE_COLLECTION_NAMES,
            CAMPAIGNS_OUT_DATA_DIR,
        )


def _create_campaign_entry(value: pd.Series, datatype: str, schemas: dict, validation: bool) -> Dict[str, Any]:
    """Create a campaign entry from DataFrame row."""
    _id = str(value["original_id"])
    entry = {
        "_key": _id,
        "original_id": str(value["original_id"]),
        "name": value["name"],
        "datatype": datatype,
        "metadata": {
            "description": value["description"],
            "type": value["type"],
        },
    }
    
    if validation:
        validate_entry(entry, schemas[datatype])
    
    return entry


def _create_campaign_edges(
    client: arango.ArangoClient,
    save_path: str,
    edge_config: Dict[str, str],
    campaign_id_map: Dict[str, str],
    datatype: str,
    schemas: dict,
    validation: bool,
    username: str,
    password: str,
):
    """Create edges between campaigns and related entities (techniques, groups, software)."""
    file_path = os.path.join(save_path, edge_config["file_name"])
    
    if not os.path.exists(file_path):
        logging.warning(f"Mapping file not found: {file_path}")
        return
    
    df = pd.read_json(file_path, lines=True)
    edge_name = edge_config["edge_name"]
    schema = schemas.get(edge_name) if validation else None
    
    db = client.db("BRON", username=username, password=password, auth_method="basic")
    collection = db.collection(edge_config["collection"])
    
    logging.info(f"Linking {len(df)} rows for {collection.name}")
    
    for _, row in tqdm(df.iterrows(), total=len(df), desc=f"Creating {edge_name} edges"):
        entity_id = str(row[edge_config["collection_key"]])
        result = query_bron(collection, {"original_id": entity_id}, warning=False)
        
        if result is None:
            continue
        
        campaign_id = row["campaign_id"]
        if campaign_id not in campaign_id_map:
            logging.warning(f"Campaign ID {campaign_id} not found in campaign_id_map")
            continue
        
        _from = f"{datatype}/{campaign_id_map[campaign_id]}"
        _to = result["_id"]
        document = create_edge_document(_from, _to, schema, validation)
        CAMPAIGNS_BRON_DATA[edge_name].append(document)


def _build_campaign(
    save_path: str,
    username: str,
    password: str,
    ip: str,
    client: arango.ArangoClient,
    validation: bool = True,
):
    """Build campaign entries and create edges in BRON database."""
    logging.info(
        f"Building campaigns in BRON for {username} on {ip} with validation: {validation} from {save_path}"
    )
    
    # Load and process campaign data
    file_path = os.path.join(save_path, "campaign.jsonl")
    if not os.path.exists(file_path):
        logging.error(f"Campaign file not found: {file_path}")
        return
    
    df = pd.read_json(file_path, lines=True)
    check_duplicates(df, ["name", "id"])
    df = df.sort_values(by=["original_id"])
    
    datatype = CAMPAIGNS_BASENAME
    schemas = get_schemas() if validation else {}
    campaign_id_map = {}

    # Create campaign entries
    for _, row in tqdm(df.iterrows(), total=len(df), desc="Processing campaigns"):
        entry = _create_campaign_entry(row, datatype, schemas, validation)
        campaign_id_map[entry["original_id"]] = entry["_key"]
        CAMPAIGNS_BRON_DATA[datatype].append(entry)

    # Define edge configurations
    edge_configs = [
        {
            "file_name": "campaign_technique_mapping.jsonl",
            "edge_name": "CampaignTechnique",
            "collection": "technique",
            "collection_key": "technique_id",
        },
        {
            "file_name": "campaign_group_mapping.jsonl",
            "edge_name": "CampaignGroup",
            "collection": "group",
            "collection_key": "group_id",
        },
        {
            "file_name": "campaign_software_mapping.jsonl",
            "edge_name": "CampaignSoftware",
            "collection": "software",
            "collection_key": "software_id",
        },
    ]
    
    # Get edge schemas if validation is enabled
    if validation:
        for config in edge_configs:
            schemas[config["edge_name"]] = get_schema(config["edge_name"])
    
    # Create edges for each mapping
    for config in edge_configs:
        _create_campaign_edges(
            client, save_path, config, campaign_id_map, datatype, schemas, validation, username, password
        )

    # Write output files
    for key, value in CAMPAIGNS_BRON_DATA.items():
        output_file = os.path.join(CAMPAIGNS_OUT_DATA_DIR, f"import_{key}.jsonl")
        write_jsonl(output_file, value)

    logging.info(f"Built {len(CAMPAIGNS_BRON_DATA[datatype])} campaign entries")


def parse_args(args: List[str]) -> Any:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Link campaigns to BRON")
    parser.add_argument("--username", type=str, required=True, help="DB username")
    parser.add_argument("--password", type=str, required=True, help="DB password")
    parser.add_argument("--ip", type=str, required=True, help="DB IP address")
    parser.add_argument("--data_folder", type=str, required=True, help="Data folder")
    parser.add_argument("--clean_db", action="store_true", help="Remove collections")
    return parser.parse_args(args)


if __name__ == "__main__":
    log_file = os.path.basename(__file__).replace(".py", ".log")
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s",
        level=logging.INFO,
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )

    args_ = parse_args(sys.argv[1:])
    if args_.clean_db:
        collections = {CAMPAIGNS_BASENAME}
        collections.update(CAMPAIGNS_EDGE_COLLECTION_NAMES.keys())
        logging.info(f"Clean {collections}")
        clean_BRON_collections(args_.username, args_.password, args_.ip, collections)
        sys.exit(0)

    build_campaign(
        args_.data_folder,
        args_.username,
        args_.password,
        args_.ip,
    )
