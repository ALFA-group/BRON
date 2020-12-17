import os

from graph_db.bron_arango import (
    DB,
    USER,
    PWD,
)
from download_threat_information.download_threat_data import main as dti_main, CVE_ALL_YEARS, OUTPUT_FOLDER, THREAT_DATA_TYPES
from download_threat_information.parsing_scripts.parse_attack_tactic_technique import link_tactic_techniques
from download_threat_information.parsing_scripts.parse_cve import parse_cve_file
from download_threat_information.parsing_scripts.parse_capec_cwe import parse_capec_cwe_files
from BRON.build_BRON import build_graph, parse_args as bb_parse_args, BRON_PATH
from graph_db.bron_arango import main as ba_main, arango_import

# TODO could maybe be bash instead of os.system from python...

BRON_SAVE_PATH = 'update_bron_data'


def main() -> None:
    # TODO make sure to clean out old files
    
    # Backup db
    cmd = ["arangodump",
           "--output-directory", "dump",
           "--overwrite", "true",
           "--server.password", PWD,
           "--server.database", DB,
           "--server.endpoint", "http+tcp://127.0.0.1:8529",
           "--server.authentication", "false",
    ]
    cmd_str = " ".join(cmd)
    # TODO not great to print PWD
    print(cmd_str)
    os.system(cmd_str)
    print("### Dumped arangodb")

    # Download latest BRON files
    dti_main(CVE_ALL_YEARS)
    print("### Downloaded threat information")

    # Link data
    out_path = OUTPUT_FOLDER
    filename = os.path.join(out_path, THREAT_DATA_TYPES['ATTACK'])
    link_tactic_techniques(filename, out_path)
    print("### Link ATTACK")
    cve_path = os.path.join(out_path, THREAT_DATA_TYPES['CVE'])
    save_path_file = "cve_map_cpe_cwe_score.json"
    save_file = os.path.join(out_path, save_path_file)
    parse_cve_file(cve_path, save_file)
    print("### Link CVE")
    capec_file = os.path.join(out_path, THREAT_DATA_TYPES['CAPEC'])
    cwe_file = os.path.join(out_path, THREAT_DATA_TYPES['CWE'])
    parse_capec_cwe_files(capec_file, cwe_file, save_path=out_path)
    print("### Link CAPEC CWE")
    
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
    print("### Built BRON")

    # BRON to arango format
    bron_json_path = os.path.join(BRON_SAVE_PATH, "BRON.json")
    ba_main(bron_json_path)
    print(f"### Created arango format from {bron_json_path}")
    # Import new BRON files
    # TODO we can use the meta data that we save when downloading data...
    arango_import()
    print("### Updated arangodb")

    
if __name__ == '__main__':
    main()
