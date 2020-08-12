import json
import argparse
import gzip
import os


def parse_cve_file(filename, save_file):
    cve_dict = {}
    with gzip.open(filename, "rt", encoding="utf-8") as f:
        cve_data = json.load(f)

        for item in cve_data["CVE_Items"]:
            cpes = set()
            cwes = set()
            score = 0
            cve_id = item["cve"]["CVE_data_meta"]["ID"]
            cve_description = item["cve"]["description"]["description_data"][0]["value"]

            for cpe_node in item["configurations"]["nodes"]:
                if "cpe_match" not in cpe_node:
                    continue
                for cpe in cpe_node["cpe_match"]:
                    if cpe["vulnerable"]:
                        cpes.add(cpe["cpe23Uri"])
                for p_data in item["cve"]["problemtype"]["problemtype_data"]:
                    for desc in p_data["description"]:
                        cwes.add(desc["value"].split("-")[1])
            if "baseMetricV2" in item["impact"]:
                score = item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
            if "baseMetricV3" in item["impact"]:
                score = (
                    score + item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                ) / 2
            entry_dict = {
                "cpes": list(cpes),
                "cwes": list(cwes),
                "score": score,
                "description": cve_description,
            }
            cve_dict[cve_id] = entry_dict
    with open(save_file, "w") as cve_f:
        cve_f.write(json.dumps(cve_dict, indent=4, sort_keys=True))


if __name__ == "__main__":
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
        action='store_true',
        help="Add argument if using only recent CVE data from 2015-2020"
    )
    args = parser.parse_args()
    cve_path = args.cve_path
    save_path = args.save_path
    only_recent_cves = args.only_recent_cves
    if only_recent_cves:
        save_path_file = "cve_map_cpe_cwe_score_2015_2020.json"
    else:
        save_path_file = "cve_map_cpe_cwe_score.json"
    save_file = os.path.join(save_path, save_path_file)
    parse_cve_file(cve_path, save_file)
