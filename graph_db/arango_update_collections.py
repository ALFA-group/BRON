import os
import logging

from graph_db.bron_arango import (
    DB,
)
from download_threat_information.download_threat_data import main as dti_main, CVE_ALL_YEARS, OUTPUT_FOLDER, THREAT_DATA_TYPES
from download_threat_information.parsing_scripts.parse_attack_tactic_technique import link_tactic_techniques
from download_threat_information.parsing_scripts.parse_cve import parse_cve_file
from download_threat_information.parsing_scripts.parse_capec_cwe import parse_capec_cwe_files
from BRON.build_BRON import build_graph, parse_args as bb_parse_args, BRON_PATH
from graph_db.bron_arango import main as ba_main, arango_import

# TODO could maybe be bash instead of os.system from python...
logging.basicConfig(filename='arango_update_collections.log', format='%(asctime)s %(levelname)s:%(message)s', level=logging.INFO)
BRON_SAVE_PATH = 'update_bron_data'


def main(username: str, password: str, ip: str) -> None:
    # TODO make sure to clean out old files
    
    # Backup db
    cmd = ["arangodump",
           "--output-directory", "dump",
           "--overwrite", "true",
           "--server.password", password,
           "--server.database", DB,
           "--server.endpoint", f"http+tcp://{ip}:8529",
           "--server.authentication", "false",
    ]
    cmd_str = " ".join(cmd)
    os.system(cmd_str)
    logging.info("Dumped arangodb")

    # Download latest BRON files
    dti_main(CVE_ALL_YEARS)
    logging.info("Downloaded threat information")

    # Link data
    out_path = OUTPUT_FOLDER
    filename = os.path.join(out_path, THREAT_DATA_TYPES['ATTACK'])
    link_tactic_techniques(filename, out_path)
    logging.info("Link ATTACK")
    cve_path = os.path.join(out_path, THREAT_DATA_TYPES['CVE'])
    save_path_file = "cve_map_cpe_cwe_score.json"
    save_file = os.path.join(out_path, save_path_file)
    parse_cve_file(cve_path, save_file)
    logging.info("Link CVE")
    capec_file = os.path.join(out_path, THREAT_DATA_TYPES['CAPEC'])
    cwe_file = os.path.join(out_path, THREAT_DATA_TYPES['CWE'])
    parse_capec_cwe_files(capec_file, cwe_file, save_path=out_path)
    logging.info("Link CAPEC CWE")
    
    # Build BRON
    # TODO here we can save compute time if we do this often...
    os.makedirs(BRON_SAVE_PATH, exist_ok=True)
    BRON_original_id_to_bron_id_path = os.path.join(BRON_SAVE_PATH, BRON_PATH)
    os.makedirs(BRON_original_id_to_bron_id_path, exist_ok=True)
    bb_args = {'input_data_folder': OUTPUT_FOLDER,
            'save_path': BRON_SAVE_PATH,
            }
    print(bb_args)
    build_graph(**bb_args)
    logging.info("Built BRON")

    # BRON to arango format
    bron_json_path = os.path.join(BRON_SAVE_PATH, "BRON.json")
    ba_main(bron_json_path)
    logging.info(f"Created arango format from {bron_json_path}")
    # Import new BRON files
    # TODO we can use the meta data that we save when downloading data...
    arango_import(username, password, ip)
    logging.info("Updated arangodb")

    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create json files to import into ArangoDb from BRON json')
    parser.add_argument("-f", type=str, default=bron_file_path,
                        help="Path to BRON.json")
    parser.add_argument("--username", type=str, required=True,
                        help="DB username")
    parser.add_argument("--password", type=str, required=True,
                        help="DB password")
    parser.add_argument("--ip", type=str, required=True,
                        help="DB IP address")
    args = parser.parse_args(sys.argv[1:])
    main(args.username, args.password, args.ip)
