import json
import sys
import argparse
import shutil
import os
import subprocess
from typing import List, Any, Set, Dict, Optional
import arango
import logging
from collections import defaultdict

import pandas as pd
from tqdm import tqdm
import yaml

from utils.mitigation_utils import (
    check_duplicates,
    update_BRON_graph_db,
    clean_BRON_collections,
    write_jsonl,
    link_data,
)
from graph_db.bron_arango import get_schemas, validate_entry


# Constants
ANALYTICS_URL = "https://github.com/mitre-attack/car.git"
ANALYTICS_RAW_DATA_DIR = "data/raw"
ANALYTICS_DATA_DIR = "data/mitigations/analytics"
ANALYTICS_BASENAME = "car"
ANALYTICS_EDGE_COLLECTION_NAMES = {
    "CarTechnique": ("car", "technique"),
    "CarTactic": ("car", "tactic"),
    "CarD3fend_mitigation": ("car", "d3fend_mitigation"),
}
ANALYTICS_BRON_DATA = defaultdict(list)


def get_analytic_files(directory: str) -> Set[str]:
    """Get all YAML analytic files from the analytics directory."""
    logging.info(f"Getting analytic files from {directory}")
    files = set()
    dir_analytics = os.path.join(directory, "analytics")
    
    try:
        if not os.path.exists(dir_analytics):
            logging.warning(f"Analytics directory not found: {dir_analytics}")
            return files
            
        for file in os.listdir(dir_analytics):
            if file.endswith(".yaml"):
                files.add(os.path.join(dir_analytics, file))
    except OSError as e:
        logging.error(f"Error reading directory {directory}: {e}")
        return files

    logging.info(f"Found {len(files)} analytic files")
    return files


def get_yaml_text(file_path: str) -> Dict[str, Any]:
    """Load and parse a YAML file."""
    logging.info(f"Loading YAML from {file_path}")
    try:
        with open(file_path, "r") as f:
            text_yaml = yaml.safe_load(f)
            return text_yaml if text_yaml else {}
    except (OSError, yaml.YAMLError) as e:
        logging.error(f"Error loading YAML from {file_path}: {e}")
        return {}


def download_analytics(output_path: str):
    """Download CAR analytics repository and extract YAML files."""
    logging.info(f"Downloading analytics from {ANALYTICS_URL} to {output_path}")
    repo_path = os.path.join(output_path, "car")
    
    # Remove existing repository if it exists
    if os.path.exists(repo_path):
        logging.info(f"Removing existing repository: {repo_path}")
        shutil.rmtree(repo_path)
    
    # Clone repository using subprocess
    try:
        subprocess.run(
            ["git", "clone", ANALYTICS_URL, repo_path],
            check=True,
            capture_output=True,
            text=True,
        )
        logging.info(f"Successfully cloned repository to {repo_path}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to clone repository: {e.stderr}")
        raise
    except FileNotFoundError:
        logging.error("git command not found. Please install git.")
        raise
    
    # Get and process analytic files
    analytic_files = get_analytic_files(repo_path)
    if not analytic_files:
        logging.warning("No analytic files found in repository")
        return
    
    analytic_data = []
    for file_path in analytic_files:
        yaml_data = get_yaml_text(file_path)
        if yaml_data:
            analytic_data.append({file_path: yaml_data})

    file_path = os.path.join(output_path, f"raw_{ANALYTICS_BASENAME}.jsonl")
    write_jsonl(file_path, analytic_data)
    logging.info(f"Downloaded and processed {len(analytic_data)} analytics")


def _extract_coverage_mappings(data: Dict[str, Any], car_id: str) -> Dict[str, List[Dict[str, str]]]:
    """Extract coverage mappings (techniques, tactics, subtechniques) from CAR data."""
    mappings = {"technique": [], "tactic": [], "d3fend": []}
    
    for coverage in data.get("coverage", []):
        for key, values in coverage.items():
            if key == "technique":
                mappings[key].append({"car_id": car_id, f"{key}_id": values})
            elif key == "tactics":
                for value in values:
                    mappings["tactic"].append({"car_id": car_id, "tactic_id": value})
            elif key == "subtechniques":
                for value in values:
                    mappings["technique"].append({"car_id": car_id, "technique_id": value})
    
    # Extract D3FEND mappings
    for d3fend_mapping in data.get("d3fend_mappings", []):
        mappings["d3fend"].append({
            "car_id": car_id,
            "d3fend_id": d3fend_mapping["id"]
        })
    
    return mappings


def parse_analytics(input_path: str, output_path: str):
    """Parse raw analytics JSONL and extract analytics data and mappings."""
    logging.info(f"Parsing analytics from {input_path} to {output_path}")
    file_path = os.path.join(input_path, f"raw_{ANALYTICS_BASENAME}.jsonl")
    
    if not os.path.exists(file_path):
        logging.error(f"Input file not found: {file_path}")
        return
    
    analytics_data = []
    all_mappings = {
        "technique": [],
        "tactic": [],
        "d3fend": [],
    }
    
    with open(file_path, "r") as fd:
        for line_num, line in enumerate(fd, 1):
            try:
                line_data = json.loads(line)
                data = list(line_data.values())[0]
                
                if not data:
                    logging.warning(f"No data in line {line_num}")
                    continue
                
                # Extract implementations (should be a list or dict)
                implementations = data.get("implementations", [])
                if not isinstance(implementations, list):
                    implementations = {}
                
                # Create analytics entry
                entry = {
                    "name": data["title"],
                    "original_id": data["id"],
                    "description": data["description"],
                    "implementations": implementations,
                }
                analytics_data.append(entry)
                
                # Extract coverage mappings
                mappings = _extract_coverage_mappings(data, data["id"])
                for key, value_list in mappings.items():
                    all_mappings[key].extend(value_list)
                    
            except (json.JSONDecodeError, KeyError) as e:
                logging.error(f"Error parsing line {line_num}: {e}")
                continue

    # Write analytics data
    output_file = os.path.join(output_path, f"{ANALYTICS_BASENAME}.jsonl")
    write_jsonl(output_file, analytics_data)
    
    # Write mapping files
    for key, value in all_mappings.items():
        mapping_file = os.path.join(
            output_path, f"{ANALYTICS_BASENAME}_{key}_mapping.jsonl"
        )
        write_jsonl(mapping_file, value)

    logging.info(f"Parsed {len(analytics_data)} analytics entries")


def build_analytics(
    save_path: str,
    username: str,
    password: str,
    ip: str,
    validation: bool = True,
    update_bron_graphdb: bool = True,
):
    """Build analytics entries in BRON database."""
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    try:
        _build_analytics(save_path, username, password, ip, client, validation)
    finally:
        client.close()
    
    if update_bron_graphdb:
        update_BRON_graph_db(
            username,
            password,
            ip,
            ANALYTICS_BRON_DATA,
            ANALYTICS_EDGE_COLLECTION_NAMES,
            ANALYTICS_DATA_DIR,
        )


def _create_car_entry(value: pd.Series, datatype: str, schemas: dict, validation: bool) -> Dict[str, Any]:
    """Create a CAR analytics entry from DataFrame row."""
    _id = str(value["original_id"])
    entry = {
        "_key": _id,
        "original_id": str(value["original_id"]),
        "name": value["name"],
        "datatype": datatype,
        "metadata": {
            "description": value["description"],
            "implementations": value["implementations"],
        },
    }
    
    if validation:
        validate_entry(entry, schemas[datatype])
    
    return entry


def _build_analytics(
    save_path: str,
    username: str,
    password: str,
    ip: str,
    client: arango.ArangoClient,
    validation: bool = True,
):
    """Build analytics entries and create edges in BRON database."""
    logging.info(
        f"Building analytics in BRON for {username} on {ip} with validation: {validation}"
    )
    
    file_path = os.path.join(save_path, f"{ANALYTICS_BASENAME}.jsonl")
    if not os.path.exists(file_path):
        logging.error(f"Analytics file not found: {file_path}")
        return
    
    df = pd.read_json(file_path, lines=True)
    check_duplicates(df, ["name", "original_id"])
    df = df.sort_values(by=["original_id"])
    
    datatype = ANALYTICS_BASENAME
    schemas = get_schemas() if validation else {}
    car_id_map = {}

    # Create CAR entries
    for _, row in tqdm(df.iterrows(), total=len(df), desc="Processing analytics"):
        entry = _create_car_entry(row, datatype, schemas, validation)
        car_id_map[entry["original_id"]] = entry["_key"]
        ANALYTICS_BRON_DATA[datatype].append(entry)

    # Connect to database and create edges
    db = client.db("BRON", username=username, password=password, auth_method="basic")
    
    # Define mapping configurations
    mapping_configs = [
        {
            "file_name": f"{ANALYTICS_BASENAME}_technique_mapping.jsonl",
            "edge_name": "CarTechnique",
            "dst": "technique_id",
            "collection_name": "technique",
        },
        {
            "file_name": f"{ANALYTICS_BASENAME}_tactic_mapping.jsonl",
            "edge_name": "CarTactic",
            "dst": "tactic_id",
            "collection_name": "tactic",
        },
        {
            "file_name": f"{ANALYTICS_BASENAME}_d3fend_mapping.jsonl",
            "edge_name": "CarD3fend_mitigation",
            "dst": "d3fend_id",
            "collection_name": "d3fend_mitigation",
        },
    ]
    
    # Create edges for each mapping
    for config in mapping_configs:
        mapping_file = os.path.join(save_path, config["file_name"])
        if os.path.exists(mapping_file):
            link_data(
                db,
                mapping_file,
                config["edge_name"],
                dst=config["dst"],
                validation=validation,
                id_map=car_id_map,
                collection_name=config["collection_name"],
                basename=ANALYTICS_BASENAME,
                data=ANALYTICS_BRON_DATA,
                id_key="car_id",
            )
        else:
            logging.warning(f"Mapping file not found: {mapping_file}")

    # Write output files
    for key, value in ANALYTICS_BRON_DATA.items():
        output_file = os.path.join(ANALYTICS_DATA_DIR, f"import_{key}.jsonl")
        write_jsonl(output_file, value)

    logging.info(f"Built {len(ANALYTICS_BRON_DATA[datatype])} analytics entries")


def main(
    username: str,
    password: str,
    ip: str,
    validation: bool = True,
    download: bool = True,
):
    """Main function to download, parse, and build analytics in BRON."""
    logging.info(
        f"Processing analytics in BRON for {username} on {ip} with validation: {validation}"
    )
    os.makedirs(ANALYTICS_DATA_DIR, exist_ok=True)
    os.makedirs(ANALYTICS_RAW_DATA_DIR, exist_ok=True)
    
    if download:
        download_analytics(ANALYTICS_RAW_DATA_DIR)
    
    parse_analytics(ANALYTICS_RAW_DATA_DIR, ANALYTICS_DATA_DIR)
    build_analytics(ANALYTICS_DATA_DIR, username, password, ip, validation)
    logging.info("Completed analytics processing")


def parse_args(args: List[str]) -> Any:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Link CAR analytics to BRON")
    parser.add_argument("--username", type=str, required=True, help="DB username")
    parser.add_argument("--password", type=str, required=True, help="DB password")
    parser.add_argument("--ip", type=str, required=True, help="DB IP address")
    parser.add_argument("--clean_db", action="store_true", help="Remove collections")
    parser.add_argument("--no_download", action="store_true", help="Skip download")
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
        collections = {
            ANALYTICS_BASENAME,
        }
        collections.update(ANALYTICS_EDGE_COLLECTION_NAMES.keys())
        logging.info(f"Clean {collections}")
        clean_BRON_collections(args_.username, args_.password, args_.ip, collections)
        sys.exit(0)

    main(
        args_.username,
        args_.password,
        args_.ip,
        download=not args_.no_download,
    )
