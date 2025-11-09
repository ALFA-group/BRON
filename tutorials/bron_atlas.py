import logging
import os

from download_threat_information.download_threat_data import _download_atlas, OUTPUT_FOLDER, THREAT_DATA_TYPES
from download_threat_information.parsing_scripts.parse_atlas import parse_atlas, ATLAS_FOLDER
from offense.build_atlas import build_atlas

USERNAME = "root"
PASSWORD = "changeme"
IP = "127.0.0.1"

def main():
    _download_atlas()
    parse_atlas(os.path.join(OUTPUT_FOLDER, THREAT_DATA_TYPES['ATLAS']), ATLAS_FOLDER)
    build_atlas(ATLAS_FOLDER, USERNAME, PASSWORD, IP, validation=True, update_bron_graphdb=True)

if __name__ == '__main__':
    log_file = os.path.basename(__file__).replace(".py", ".log")
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s",
        level=logging.INFO,
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )    
    main()
    