from typing import Dict, Any
import os
import json
import sys
import argparse
import logging

import arango
import dotenv

from graph_db.bron_arango import DB, validate_entry
from utils.mitigation_utils import (
    import_into_arango,
    query_bron,
    update_graph_in_graph_db,
)


def make_edges(
    out_file: str,
    validation: bool,
    edge_file: str,
    schema: Dict[str, Any],
    collection_name,
    db: Any,
):
    logging.info(f"Begin make edges with {edge_file}")
    edges = []
    bron_collection = db.collection(collection_name)

    with open(edge_file, "r") as fd:
        data = json.load(fd)

    for key, values in data.items():
        for value in values:
            try:
                _from = query_bron(bron_collection, {"original_id": key})["_id"]
            except TypeError as e:
                logging.error(f"{key} not found in {bron_collection}. {e}")
                continue

            try:
                _to = query_bron(bron_collection, {"original_id": value})["_id"]
            except TypeError as e:
                logging.error(f"{value} not found in {bron_collection}. {e}")
                continue

            entry = {"_from": _from, "_to": _to}
            if validation:
                validate_entry(entry, schema)

            edges.append(entry)

    with open(out_file, "w") as fd:
        for edge in edges:
            json.dump(edge, fd)
            fd.write("\n")

    logging.info(f"Done {edge_file} to {out_file}")


def update_edges_between_same_datasources(username: str, password: str, ip: str, validation: True):
    datasource_edge_files = (
        (
            "data/attacks/technique_sub_technique_map.json",
            "graph_db/schemas/edge_collections/TechniqueTechnique_schema.json",
            "technique",
        ),
        (
            "data/attacks/capec_capec_map.json",
            "graph_db/schemas/edge_collections/CapecCapec_schema.json",
            "capec",
        ),
        (
            "data/attacks/cwe_cwe_map.json",
            "graph_db/schemas/edge_collections/CweCwe_schema.json",
            "cwe",
        ),
    )
    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    db = client.db(DB, username=username, password=password, auth_method="basic")
    for edge_file, schema_file, collection_name in datasource_edge_files:
        logging.info(f"Begin make edges with {edge_file} {schema_file} {collection_name}")
        schema = {}
        if validation:
            with open(schema_file, "r") as fd:
                schema = json.load(fd)
        edge_collection = schema_file.split("/")[-1].replace("_schema.json", "")
        out_file = os.path.join(os.path.dirname(edge_file), f"{edge_collection}.jsonl")
        make_edges(out_file, validation, edge_file, schema, collection_name, db)
        import_into_arango(username, password, ip, out_file, edge_keys=True, name=schema["title"])
        update_graph_in_graph_db(
            username,
            password,
            ip,
            collection_name=schema["title"],
            edge_key=(collection_name, collection_name),
        )
        logging.info(f"Done updating {DB} with {edge_file} to {schema['title']}")

    client.close()
    logging.info(f"Done updating {DB} with same data sources")


if __name__ == "__main__":
    log_file = os.path.basename(__file__).replace(".py", ".log")
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s",
        level=logging.INFO,
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )

    parser = argparse.ArgumentParser(description="Create edges between same datasources")
    args = parser.parse_args(sys.argv[1:])
    dotenv.load_dotenv()
    password_ = str(os.environ.get("BRON_PWD"))
    username_ = "root"
    ip_ = str(os.environ.get("BRON_SERVER_IP"))
    update_edges_between_same_datasources(username_, password_, ip_, True)
