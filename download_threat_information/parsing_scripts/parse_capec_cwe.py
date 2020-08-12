import pandas as pd
import json
import zipfile
import os
import argparse


def parse_capec_cwe_files(capec_file, cwe_file, save_path):
    # Create dictionaries for parsed data
    capec_names_dict = dict()
    cwe_names_dict = dict()
    capec_cwe_mapping_dict = {"capec_cwe": dict()}

    # Load CAPEC and CWE data
    with open(capec_file, "r") as capec_data:
        capec_data = json.load(capec_data)
    cwe_zip = zipfile.ZipFile(cwe_file)
    cwe_data = pd.read_csv(cwe_zip.open('1000.csv'))

    # Make capec_names_dict
    capec_objects = capec_data["objects"][2:]
    for capec_entry in capec_objects:
        if "external_references" in capec_entry.keys():
            external_id = capec_entry["external_references"][0]["external_id"]
            _, capec_id = external_id.split('-')
            capec_name = capec_entry["name"]
            capec_names_dict[capec_id] = capec_name

    # Make cwe_names_dict
    for row_index in cwe_data.index:
        cwe_id = cwe_data["CWE-ID"][row_index]
        cwe_names_dict[str(row_index)] = cwe_id

    # Make capec_cwe_mapping_dict
    for capec_entry in capec_objects:
        if "external_references" in capec_entry.keys():
            external_references = capec_entry["external_references"]
            _, capec_id = external_references[0]["external_id"].split('-')
            capec_cwes = []
            for ref in external_references:
                if ref["source_name"] == "cwe":
                    _, cwe_id = ref["external_id"].split('-')
                    capec_cwes.append(cwe_id)
            capec_cwe_mapping_dict["capec_cwe"][capec_id] = {"cwes": capec_cwes}

    # Save parsed data
    with open(os.path.join(save_path, "capec_names.json"), "w") as save_capec_names:
        save_capec_names.write(json.dumps(capec_names_dict, indent=4, sort_keys=True))
    with open(os.path.join(save_path, "cwe_names.json"), "w") as save_cwe_names:
        save_cwe_names.write(json.dumps(cwe_names_dict, indent=4, sort_keys=True))
    with open(os.path.join(save_path, "capec_cwe_mapping.json"), "w") as save_capec_cwe_mapping:
        save_capec_cwe_mapping.write(json.dumps(capec_cwe_mapping_dict, indent=4, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse raw_CAPEC.json and raw_CWE.zip")
    parser.add_argument("--capec_file", type=str, required=True, help="File path to raw_CAPEC.json")
    parser.add_argument("--cwe_file", type=str, required=True, help="File path to raw_CWE.zip")
    parser.add_argument("--save_path", type=str, required=True, help="Folder path to save parsed data")
    args = parser.parse_args()
    capec_file = args.capec_file
    cwe_file = args.cwe_file
    save_path = args.save_path
    parse_capec_cwe_files(capec_file, cwe_file, save_path)
