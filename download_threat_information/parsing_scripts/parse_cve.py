import json
import argparse
import gzip
import os
import logging
from typing import Dict, Any, List, Tuple, Set

RECENT_CVE_MAP_FILE = "cve_map_cpe_cwe_score_last_five_years.json"
CVE_MAP_FILE = "cve_map_cpe_cwe_score.json"


def match_cpes(node: Dict[str, Any]):
    # TODO filter out some empty fields
    return node
    
def parse_cve_file(filename, save_file):
    logging.info(f"Begin parse CVE files from {filename}")
    cve_dict = {}
    with gzip.open(filename, "rt", encoding="utf-8") as f:
        cve_data = json.load(f)
        for item in cve_data["vulnerabilities"]:
            cwes = set()
            score = 0
            cve_id = item["cve"]["id"]
            # TODO assumes english first...
            cve_description = item["cve"]["descriptions"][0]["value"]
            assert item["cve"]["descriptions"][0]["lang"] == "en"
            cpes = []
            for cfg in item["cve"].get("configurations", []):
                _cpes = match_cpes(cfg["nodes"])
                cpes.append(_cpes)            
            
            for p_data in item["cve"].get("weaknesses", []):
                for desc in p_data["description"]:
                    cwes.add(desc["value"].split("-")[1])

            impact = item["cve"]['metrics']
            scores = []
            for key, metrics in impact.items():
                for metric in metrics:
                    scores.append(metric.get('cvssData', 0).get("baseScore", 0))

            if scores:
                score = sum(scores) / len(scores)
                
            assert 0 <= score <= 10
            exploits = get_exploit_references(item['cve'])
            # TODO assert more score range
            assert score >= 0
            entry_dict = {
                "cpes": cpes,
                "cwes": list(cwes),
                "score": score,
                "description": cve_description,
                "impact": impact,
                "exploits": exploits
            }
            cve_dict[cve_id] = entry_dict

    with open(save_file, "w") as cve_f:
        cve_f.write(json.dumps(cve_dict, indent=4, sort_keys=True))

    assert os.path.exists(save_file)
    logging.info(f"Parsed CVE files from {filename} to {save_file}")

def get_exploit_references(entry: Dict[str, Any]) -> List[str]:
    exploits = []
    for reference in entry.get('references', []):
        element = reference.get('tags', [])
        if "Exploit" in element:
            exploits.append(reference['url'])
            
    return exploits

if __name__ == "__main__":
    log_file = os.path.basename(__file__).replace(".py", ".log")
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s",
        level=logging.INFO,
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )

    parser = argparse.ArgumentParser(description="Parse CVE File")
    parser.add_argument(
        "--cve_path", type=str, required=True, help="File path to raw_CVE.json.gz"
    )
    parser.add_argument(
        "--save_path",
        type=str,
        required=True,
        help="Folder path to save parsed data",
    )
    parser.add_argument(
        "--only_recent_cves",
        action="store_true",
        help="Add argument if using only recent CVE data from last five years",
    )
    args = parser.parse_args()
    cve_path = args.cve_path
    save_path = args.save_path
    only_recent_cves = args.only_recent_cves
    if only_recent_cves:
        save_path_file = RECENT_CVE_MAP_FILE
    else:
        save_path_file = CVE_MAP_FILE

    save_file_ = os.path.join(save_path, save_path_file)
    parse_cve_file(cve_path, save_file_)
