import json
import os
import argparse


def link_tactic_techniques(file_name, save_path):
    technique_tactic_dict = {}
    capec_technique_dict = {}
    technique_id_name_dict = {}
    with open(file_name, "r") as enterprise:
        data = json.load(enterprise)
        object_list = data["objects"]
        for entry in object_list:
            tactics_set = set()
            if "external_references" in entry.keys():
                references = entry["external_references"]
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
            if "name" in entry.keys():
                technique_id_name_dict[technique_id] = entry["name"]
            if "kill_chain_phases" in entry.keys():
                phases = entry["kill_chain_phases"]
                for phase in phases:
                    tactics_set.add(phase["phase_name"])
            technique_tactic_dict[technique_id] = list(tactics_set)
    with open(os.path.join(save_path, "capec_technique_map.json"), "w") as save:

        save.write(json.dumps(capec_technique_dict, indent=4, sort_keys=True))
    with open(os.path.join(save_path, "technique_tactic_map.json"), "w") as save2:
        save2.write(json.dumps(technique_tactic_dict, indent=4, sort_keys=True))
    with open(os.path.join(save_path, "technique_name_map.json"), "w") as save3:
        save3.write(json.dumps(technique_id_name_dict, indent=4, sort_keys=True))


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
