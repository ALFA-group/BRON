import logging
import os
import argparse
import pandas as pd
from typing import Dict, List, Tuple

import yaml

from utils.mitigation_utils import write_jsonl


ATLAS_FILE_NAME = 'ATLAS.json'
ATLAS_FOLDER = 'data/attacks/atlas'


def create_mapping_dict(key1: str, key2: str) -> Dict[str, List]:
    """Create a dictionary for storing mapping relationships."""
    return {key1: [], key2: []}


def save_mapping(mapping: Dict[str, List], save_folder: str, filename: str):
    """Save a mapping dictionary to a JSONL file."""
    df = pd.DataFrame(mapping)
    filepath = os.path.join(save_folder, filename)
    df.to_json(filepath, lines=True, orient='records')
    count = len(mapping[list(mapping.keys())[0]])
    logging.info(f"Saved {count} mappings to {filename}")


def parse_tactics(data: Dict, save_folder: str) -> Tuple[List[Dict], Dict[str, List]]:
    """Parse ATLAS tactics and create mappings to ATT&CK tactics."""
    tactics = []
    tactic_attack_map = create_mapping_dict('atlas_tactic_id', 'tactic_id')
    
    for item in data['tactics']:
        _id = item['id']
        entry = {
            'name': item['name'],
            'original_id': _id,
            'description': item['description'],
        }
        tactics.append(entry)
        
        if 'ATT&CK-reference' in item:
            attack_id = item['ATT&CK-reference']['id']
            assert attack_id.startswith('TA'), f"Invalid ATT&CK tactic ID: {attack_id}"
            tactic_attack_map['atlas_tactic_id'].append(_id)
            tactic_attack_map['tactic_id'].append(attack_id)
    
    write_jsonl(os.path.join(save_folder, 'atlas_tactics.jsonl'), tactics)
    save_mapping(tactic_attack_map, save_folder, 'atlas_tactic-attack_tactic_map.jsonl')
    
    logging.info(f"Parsed {len(tactics)} ATLAS tactics with {len(tactic_attack_map['atlas_tactic_id'])} ATT&CK links")
    return tactics, tactic_attack_map


def parse_techniques(data: Dict, save_folder: str) -> Tuple[List[Dict], Dict[str, List], Dict[str, List]]:
    """Parse ATLAS techniques and create mappings to tactics and ATT&CK techniques."""
    techniques = []
    tactic_technique_map = create_mapping_dict('atlas_tactic_id', 'atlas_technique_id')
    technique_attack_map = create_mapping_dict('atlas_technique_id', 'technique_id')
    
    for item in data['techniques']:
        _id = item['id']
        entry = {
            'name': item['name'],
            'original_id': _id,
            'description': item['description'],
        }
        techniques.append(entry)
        
        for tactic in item.get('tactics', []):
            tactic_technique_map['atlas_tactic_id'].append(tactic)
            tactic_technique_map['atlas_technique_id'].append(_id)
        
        if 'ATT&CK-reference' in item:
            attack_id = item['ATT&CK-reference']['id']
            assert attack_id.startswith('T'), f"Invalid ATT&CK technique ID: {attack_id}"
            technique_attack_map['atlas_technique_id'].append(_id)
            technique_attack_map['technique_id'].append(attack_id)
    
    write_jsonl(os.path.join(save_folder, 'atlas_techniques.jsonl'), techniques)
    save_mapping(tactic_technique_map, save_folder, 'atlas_tactic-atlas_technique_map.jsonl')
    save_mapping(technique_attack_map, save_folder, 'atlas_technique-attack_technique_map.jsonl')
    
    logging.info(
        f"Parsed {len(techniques)} ATLAS techniques with "
        f"{len(tactic_technique_map['atlas_tactic_id'])} tactic links and "
        f"{len(technique_attack_map['atlas_technique_id'])} ATT&CK links"
    )
    return techniques, tactic_technique_map, technique_attack_map


def parse_mitigations(data: Dict, save_folder: str) -> Tuple[List[Dict], Dict[str, List], Dict[str, List]]:
    """Parse ATLAS mitigations and create mappings to techniques and ATT&CK mitigations."""
    mitigations = []
    mitigation_technique_map = create_mapping_dict('atlas_mitigation_id', 'atlas_technique_id')
    mitigation_attack_map = create_mapping_dict('atlas_mitigation_id', 'technique_mitigation_id')
    
    for item in data['mitigations']:
        _id = item['id']
        entry = {
            'name': item['name'],
            'original_id': _id,
            'description': item['description'],
            'tags': ','.join(item.get('tags', []))
        }
        mitigations.append(entry)
        
        for technique in item.get('techniques', []):
            mitigation_technique_map['atlas_mitigation_id'].append(_id)
            mitigation_technique_map['atlas_technique_id'].append(technique['id'])
        
        if 'ATT&CK-reference' in item:
            attack_id = item['ATT&CK-reference']['id']
            assert attack_id.startswith('M'), f"Invalid ATT&CK mitigation ID: {attack_id}"
            mitigation_attack_map['atlas_mitigation_id'].append(_id)
            mitigation_attack_map['technique_mitigation_id'].append(attack_id)
    
    write_jsonl(os.path.join(save_folder, 'atlas_mitigations.jsonl'), mitigations)
    save_mapping(mitigation_technique_map, save_folder, 'atlas_mitigation-atlas_technique_map.jsonl')
    save_mapping(mitigation_attack_map, save_folder, 'atlas_mitigation-attack_mitigation_map.jsonl')
    
    logging.info(
        f"Parsed {len(mitigations)} ATLAS mitigations with "
        f"{len(mitigation_technique_map['atlas_mitigation_id'])} technique links and "
        f"{len(mitigation_attack_map['atlas_mitigation_id'])} ATT&CK links"
    )
    return mitigations, mitigation_technique_map, mitigation_attack_map


def parse_atlas(atlas_path: str, save_folder: str):
    """Parse ATLAS YAML file and extract tactics, techniques, and mitigations."""
    logging.info(f"Begin parsing ATLAS file from {atlas_path} to {save_folder}")
    
    with open(atlas_path, 'r') as fd:
        data = yaml.safe_load(fd)['matrices'][0]
    
    os.makedirs(save_folder, exist_ok=True)
    
    parse_tactics(data, save_folder)
    parse_techniques(data, save_folder)
    parse_mitigations(data, save_folder)
    
    # TODO: Case studies (a version of Campaigns in ATT&CK?)
    logging.info(f"Finished parsing ATLAS to {save_folder}")


if __name__ == "__main__":
    log_file = os.path.basename(__file__).replace(".py", ".log")
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s",
        level=logging.INFO,
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )

    parser = argparse.ArgumentParser(description="Parse ATLAS File")
    parser.add_argument(
        "--atlas_path", type=str, required=True, help="File path to raw_atlas.yaml"
    )
    parser.add_argument(
        "--save_path",
        type=str,
        required=True,
        help="Folder path to save parsed data",
    )
    args = parser.parse_args()
    
    parse_atlas(args.atlas_path, args.save_path)
