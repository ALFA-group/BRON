import json
import os
import argparse

from BRON.build_BRON import name_map_paths


def link_tactic_techniques(file_name, save_path):
    technique_tactic_dict = {}
    capec_technique_dict = {}
    technique_id_name_dict = {}
    tactic_id_name_dict = {}
    with open(file_name, "r") as enterprise:
        data = json.load(enterprise)
        object_list = data["objects"]
        for entry in object_list:
            tactics_set = set()
            technique_id = ''
            if "external_references" in entry.keys():
                references = entry["external_references"]
                # TODO refactor to take better account of naming
                if len(references) > 0:
                    for ref in references:
                        if "url" in ref.keys():
                            if "https://attack.mitre.org/techniques/" in ref["url"]:
                                technique_id = ref["external_id"]
                            if ref["source_name"] == "capec":
                                capec_id = ref["external_id"]
                                split = capec_id.split("-")
                                if split[1] not in capec_technique_dict.keys():
                                    capec_technique_dict[split[1]] = [technique_id]
                                else:
                                    capec_technique_dict[split[1]].append(technique_id)

            if entry.get('id','').startswith('x-mitre-tactic--'):
                # TODO messy
                external_id = entry['external_references'][0]['external_id']
                short_name = entry['x_mitre_shortname']
                tactic_id_name_dict[short_name] = external_id
            elif "name" in entry.keys():
                technique_id_name_dict[technique_id] = entry["name"]
                
            if "kill_chain_phases" in entry.keys():
                phases = entry["kill_chain_phases"]
                for phase in phases:
                    tactics_set.add(phase["phase_name"])

            technique_tactic_dict[technique_id] = list(tactics_set)

    save_files = {name_map_paths['capec_names']: capec_technique_dict,
                  name_map_paths['tactic_map']: technique_tactic_dict,
                  name_map_paths['technique_names']: technique_id_name_dict,
                  name_map_paths['tactic_names']: tactic_id_name_dict,
                  }
    for file_name, values in save_files.items():
        with open(os.path.join(save_path, file_name), "w") as fd:
            fd.write(json.dumps(values, indent=4, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Parse enterprise-attack.json to get tactic-technique and capec-technique links"
    )
    parser.add_argument(
        "--filename", type=str, required=True, help="File path to raw_enterprise_attack.json"
    )
    parser.add_argument(
        "--save_path", type=str, required=True, help="Folder path to save parsed data"
    )
    args = parser.parse_args()
    link_tactic_techniques(args.filename, args.save_path)
