# TODO sometimes th notebooks do not play well with the arango connections.
# TODO as a notebook
import os
import shutil
import sys
import argparse
import logging
from typing import List, Any

import arango

import download_threat_information.download_threat_data as download_threat_data
from download_threat_information.download_threat_data import (
    CVE_ALL_YEARS,
    CVE_RECENT_YEARS,
    OUTPUT_FOLDER as DOWNLOAD_PATH,
)
from download_threat_information.parsing_scripts.parse_cve import parse_cve_file
import download_threat_information.parsing_scripts.parse_capec_cwe as parse_capec_cwe
import download_threat_information.parsing_scripts.parse_attack_tactic_technique as parse_attack
import offense.build_offensive_BRON as build_offensive_BRON
from offense.build_software_and_groups import build_software_and_groups, SG_OUT_DATA_DIR
import graph_db.bron_arango as bron_arango
import mitigations.d3fend_mitigations as d3fend
import mitigations.engage_mitigations as engage
import mitigations.technique_mitigations as attack_mitigations
import mitigations.capec_mitigations as capec_mitigations
import mitigations.cwe_mitigations as cwe_mitigations
from graph_db.same_datasource_links import update_edges_between_same_datasources


BRON_SAVE_PATH = "data/attacks"
MBRON_SAVE_PATH = "data/mitigations"


def parse_args(args: List[str]) -> Any:
    parser = argparse.ArgumentParser(description="Build BRON in Arango DB")
    parser.add_argument("--username", type=str, required=True, help="DB username")
    parser.add_argument("--password", type=str, required=True, help="DB password")
    parser.add_argument("--ip", type=str, required=True, help="DB IP address")
    # Clean
    parser.add_argument("--clean", action="store_true", help="Clean all files and db")
    parser.add_argument("--clean_local_files", action="store_true", help="Clean all local files")
    # Mainly used for debugging
    parser.add_argument("--no_download", action="store_true", help="Do not download data")
    parser.add_argument("--no_parsing", action="store_true", help="Do not parse data")
    parser.add_argument("--no_building", action="store_true", help="Do not build BRON")
    parser.add_argument("--only_recent", action="store_true", help="Only recent CVEs")
    parser.add_argument(
        "--no_arangodb",
        action="store_true",
        help="Do not create and import to Arangodb",
    )
    parser.add_argument(
        "--no_mitigations",
        action="store_true",
        help="Do not create and import mitigations",
    )
    parser.add_argument(
        "--no_validation",
        action="store_true",
        help="Do not validate entries imported to the ArangoDb",
    )
    args = parser.parse_args(args)
    return args


def _download(only_recent: bool=False):
    # Download
    if only_recent:
        cve_years = CVE_RECENT_YEARS
    else:
        cve_years = CVE_ALL_YEARS
    logging.info(f"BEGIN Download {cve_years}")
    
    download_threat_data.main(cve_years)
    logging.info("Downloaded threat data")


def _parse():
    logging.info("BEGIN Parsing")
    # CVE
    parse_cve_file(
        os.path.join(DOWNLOAD_PATH, "raw_CVE.json.gz"),
        os.path.join(BRON_SAVE_PATH, "cve_map_cpe_cwe_score.json"),
    )
    logging.info("Parsed CVEs")
    # CWE & CAPEC
    parse_capec_cwe.parse_cwe_xml_to_csv(
        os.path.join(DOWNLOAD_PATH, "raw_CWE_xml.zip"), BRON_SAVE_PATH, DOWNLOAD_PATH
    )
    logging.info("Parsed CWE xml")
    parse_capec_cwe.parse_capec_xml_to_csv(
        os.path.join(DOWNLOAD_PATH, "raw_CAPEC.xml"), BRON_SAVE_PATH
    )
    logging.info("Parsed CAPEC xml")
    parse_capec_cwe.parse_capec_cwe_files(
        BRON_SAVE_PATH,
    )
    logging.info("Parsed CAPEC and CWE")
    # ATT&CK
    parse_attack.parse_enterprise_attack(
        os.path.join(DOWNLOAD_PATH, "raw_enterprise_attack.json"), BRON_SAVE_PATH
    )
    logging.info("Parsed ATT&CK")
    parse_attack.link_tactic_techniques(
        os.path.join(DOWNLOAD_PATH, "raw_enterprise_attack.json"), BRON_SAVE_PATH
    )
    logging.info("Linked Tactics and Techniques")
    parse_attack.link_technique_technique(
        os.path.join(DOWNLOAD_PATH, "raw_enterprise_attack.json"), BRON_SAVE_PATH
    )
    logging.info("Linked Techniques")
    parse_attack.link_capec_technique(
        BRON_SAVE_PATH
    )
    logging.info("Linked CAPEC and Techniques")


def _build():
    logging.info("BEGIN building BRON")
    # TODO drop this step and go directly to Arango, so for simplification remove it
    build_offensive_BRON.BRON_PATH = "."
    build_offensive_BRON.build_graph(BRON_SAVE_PATH, BRON_SAVE_PATH)
    logging.info("Built BRON")


def _arangodb(username: str, password: str, ip: str, no_validation):
    logging.info("BEGIN Import BRON into Arangodb")
    bron_arango.main(
        os.path.join(BRON_SAVE_PATH, "BRON.json"),
        username,
        password,
        ip,
        not no_validation,
    )
    logging.info("Prepared BRON for Arangodb")
    bron_arango.arango_import(username, password, ip)
    logging.info("Import BRON into Arangodb")
    update_edges_between_same_datasources(username, password, ip, not no_validation)
    logging.info("Import same datasource links into Arangodb")
    build_software_and_groups(SG_OUT_DATA_DIR, username, password, ip, not no_validation)
    


def clean(username: str, password: str, ip: str, clean_local_files: bool = True):
    logging.info("BEGIN Cleaning")
    download_threat_data.clean()
    logging.info(f"Cleaned {DOWNLOAD_PATH}")

    for path in (BRON_SAVE_PATH, MBRON_SAVE_PATH):
        try:
            shutil.rmtree(path)
        except FileNotFoundError as e:
            logging.warning(e)

        os.makedirs(path)
        logging.info(f"Cleaned {path}")

    logging.info("DONE cleaning local files")
    if clean_local_files:
        logging.info("DONE Local cleaning")
        return

    client = arango.ArangoClient(hosts=f"http://{ip}:8529")
    db = client.db("_system", username=username, password=password, auth_method="basic")
    try:
        db.delete_database(bron_arango.DB)
    except arango.exceptions.DatabaseDeleteError as e:
        logging.warning(e)

    db.create_database(bron_arango.DB)
    client.close()
    logging.info(f"Deleted {bron_arango.DB}")
    logging.info("DONE cleaning")


def _mitigations(username: str, password: str, ip: str, validation: bool):
    # Build BRON Arango
    # D3FEND
    d3fend.main()
    logging.info("Created d3fend for BRON")
    d3fend.update_BRON_graph_db(username, password, ip, validation)
    logging.info("Updated d3fend in Arango")

    # Engage
    engage.main(no_download=False)
    logging.info("Created engage for BRON")
    engage.update_BRON_graph_db(username, password, ip, validation)
    logging.info("Updated engage in Arango")
   
    # ATT&CK
    attack_mitigations.main(BRON_SAVE_PATH, username, password, ip, validation)
    logging.info("Created ATTA&CK for BRON")
    attack_mitigations.update_BRON_graph_db(username, password, ip)
    logging.info("Updated ATT&CK in Arango")

    # CAPEC
    capec_mitigations.main(
        os.path.join(BRON_SAVE_PATH, "capec_from_xml.json"),
        username,
        password,
        ip,
        validation,
    )
    logging.info("Created CAPEC for BRON")
    capec_mitigations.update_BRON_graph_db(username, password, ip)
    logging.info("Updated CAPEC in Arango")

    # CWE
    cwe_mitigations.main(
        os.path.join(BRON_SAVE_PATH, "cwe_from_xml.json"),
        username,
        password,
        ip,
        validation,
    )
    logging.info("Created CWE for BRON")
    cwe_mitigations.update_BRON_graph_db(username, password, ip)
    logging.info("Updated CWE in Arango")

    # TODO CVE


def main(
    username: str,
    password: str,
    ip: str,
    no_download: bool = False,
    no_parsing: bool = False,
    no_building: bool = False,
    no_arangodb: bool = False,
    no_mitigations: bool = False,
    no_validation: bool = False,
    only_recent: bool=False
):
    # TODO change import to not create duplicates
    logging.info("BEGIN building BRON")
    if not no_download:
        _download(only_recent)

    # Parse
    if not no_parsing:
        # TODO list which fields are used for parsing raw to bron (should be related to schema)
        # TODO add URL field?
        _parse()

    # Build BRON
    if not no_building:
        _build()

    # Build Arango
    if not no_arangodb:
        _arangodb(username, password, ip, no_validation)

    if not no_mitigations:
        # TODO refactor legacy division of building attacker and then mitigations seperately
        _mitigations(username, password, ip, not no_validation)

    logging.info("END building BRON")


if __name__ == "__main__":
    log_file = os.path.basename(__file__).replace(".py", ".log")
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s",
        level=logging.INFO,
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )

    args_ = parse_args(sys.argv[1:])
    os.makedirs(BRON_SAVE_PATH, exist_ok=True)
    if args_.clean:
        clean(args_.username, args_.password, args_.ip, args_.clean_local_files)
        sys.exit(0)

    main(
        args_.username,
        args_.password,
        args_.ip,
        args_.no_download,
        args_.no_parsing,
        args_.no_building,
        args_.no_arangodb,
        args_.no_mitigations,
        args_.no_validation,
        args_.only_recent
    )
