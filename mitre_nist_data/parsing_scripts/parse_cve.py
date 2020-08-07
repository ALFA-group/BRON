import json
import argparse


def parse_cve_file(filename, save_path):
    cve_dict = {}
    with open(filename) as f:
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
    with open(save_path, "w") as cve_f:
        cve_f.write(json.dumps(cve_dict, indent=4, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse CVE File")
    parser.add_argument(
        "--cve_path", type=str, required=True, help="Location of saved CVE data"
    )
    parser.add_argument(
        "--save_path",
        type=str,
        required=True,
        help="Location to save CVE data e.g. data/pasred_data/cve_map_to_score_cwe.json",
    )
    args = parser.parse_args()
    cve_path = args.cve_path
    save_path = args.save_path
    parse_cve_file(cve_path, save_path)
