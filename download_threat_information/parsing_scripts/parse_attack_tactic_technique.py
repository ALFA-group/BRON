import json
import logging
import sys
import os
import argparse
import collections
from typing import Dict, Any

import stix2

from offense.build_offensive_BRON import DESCRIPTION_MAP_PATHS, NAME_MAP_PATHS


# TODO refactor separation of mitigation and attacks. I.e. BRON is attacks, then extension is mitigations which should be separable

TECHNIQUE_MITIGATION_VALUES = (
    "technique_detection",
    "technique_mitigation",
    "technique_mitigation_technique_mapping",
)


def link_tactic_techniques(file_name_: str, save_path: str):
    logging.info(f"Begin link ATT&CK Tactic and Technique in {file_name_}")
    technique_tactic_dict = {}
    capec_technique_dict = {}
    technique_id_name_dict = {}
    tactic_id_name_dict = {}
    tactic_descriptions = {}
    technique_descriptions = {}
    mitigation_name_dict = {}
    with open(file_name_, "r") as enterprise:
        data = json.load(enterprise)
        object_list = data["objects"]
        for entry in object_list:
            if entry.get("x_mitre_deprecated", False) or entry.get("revoked", False):
                logging.info(f"Revoked or deprecated entry {entry.get('name')} {entry.get('id')}")
                continue

            tactics_set = set()
            technique_id = ""
            entry_id = entry.get("id", "")
            entry_name = entry.get("name", "")
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

            if entry_id.startswith("x-mitre-tactic--"):
                # TODO messy
                external_id = entry["external_references"][0]["external_id"]
                short_name = entry["x_mitre_shortname"]
                assert external_id.startswith("TA")
                tactic_id_name_dict[short_name] = external_id
                tactic_descriptions[external_id] = entry.get("description", "")

            elif entry_name and technique_id != "":
                assert technique_id.startswith("T") and not technique_id.startswith("TA")
                technique_id_name_dict[technique_id] = entry_name
                technique_descriptions[technique_id] = entry.get("description", "")

            if "kill_chain_phases" in entry.keys():
                phases = entry["kill_chain_phases"]
                for phase in phases:
                    tactics_set.add(phase["phase_name"])

            if entry_id.startswith("course-of-action"):
                external_ids = []
                for external_reference in entry.get("external_references"):
                    external_id = external_reference.get("external_id")
                    if external_id is not None:
                        external_ids.append(external_id)

                if entry_id and entry_name:
                    mitigation_name_dict[entry_id] = {
                        "name": entry_name,
                        "external_ids": external_ids,
                    }

            if technique_id != "":
                technique_tactic_dict[technique_id] = list(tactics_set)

    save_files = {
        NAME_MAP_PATHS["attack_map"]: capec_technique_dict,
        NAME_MAP_PATHS["tactic_map"]: technique_tactic_dict,
        NAME_MAP_PATHS["technique_names"]: technique_id_name_dict,
        NAME_MAP_PATHS["tactic_names"]: tactic_id_name_dict,
        NAME_MAP_PATHS["mitigations_name_map"]: mitigation_name_dict,
        DESCRIPTION_MAP_PATHS["tactic_descriptions"]: tactic_descriptions,
        DESCRIPTION_MAP_PATHS["technique_descriptions"]: technique_descriptions,
    }
    for file_name_, values in save_files.items():
        file_path = os.path.join(save_path, file_name_)
        with open(file_path, "w") as fd:
            fd.write(json.dumps(values, indent=4, sort_keys=True))

        assert os.path.exists(file_path)
        logging.info(f"Wrote to disk: {file_name_}")


def _get_attack_id(entry: Dict[str, Any]) -> str:
    technique_id = ""
    for external_reference in entry.get("external_references"):
        external_id = external_reference.get("external_id", "")
        if external_reference.get("source_name") == "mitre-attack":
            # It is a technique
            technique_id = external_id
            break

    # TODO assert technique_id != ""
    return technique_id


def _get_attack_mitigation_id(entry: Dict[str, Any]) -> str:
    technique_id = ""
    for external_reference in entry.get("external_references"):
        external_id = external_reference.get("external_id", "")
        if external_reference.get("source_name") == "mitre-attack" and external_reference.get(
            "external_id", ""
        ).startswith("M"):
            # It is a mitigation
            technique_id = external_id
            break

    return technique_id


# TODO ATTACK and CAPEC data in stix format, use that for parsing
def parse_enterprise_attack(file_name: str, save_path: str):
    logging.info(f"Begin parse ATT&CK data from {file_name}")
    # TODO for handling of bronsprak
    # TODO this can be parsed with stix2 library
    ATTACK_DATA = {
        "attack-pattern",
        "course-of-action",
        "intrusion-set",
        "tool",
        "malware",
    }
    ATTACK_RELATIONSHIP_DATA = {"mitigates", "uses"}
    REF_BRON_MAP = {
        "malware": "software",
        "tool": "software",
        "intrusion-set": "group",
        "attack-pattern": "technique",
    }
    values = collections.defaultdict(list)
    with open(file_name, "r") as fd:
        data = json.load(fd)

    attack_id_to_technique_id_map = {}
    for entry in data["objects"]:
        id_ = entry.get("id", "")
        name_ = entry.get("name", "")
        type_ = entry.get("type", "")
        if type_ in ATTACK_DATA:
            if entry.get("x_mitre_deprecated", False) or entry.get("revoked", False):
                logging.info(f"Revoked or deprecated entry {entry.get('name')} {entry.get('id')}")
                continue

            if type_ == "attack-pattern" and entry.get("x_mitre_detection", ""):
                technique_id = _get_attack_id(entry)
                category = "x_mitre_detection"
                # TODO look at the data component and data source types
                # TODO this makes no sense, there is no detection information here. Look at "indicators" instead
                values["technique_detection"].append(
                    {
                        "name": name_,
                        "original_id": technique_id,
                        "detection": entry[category],
                        "id": id_,
                    }
                )
                attack_id_to_technique_id_map[id_] = technique_id
            elif type_ == "intrusion-set":
                group_id = _get_attack_id(entry)
                assert group_id.startswith("G")
                # TODO are the aliases internal links?
                values["group"].append(
                    {
                        "name": name_,
                        "original_id": group_id,
                        "description": entry["description"],
                        "aliases": entry.get("aliases", [""]),
                        "id": id_,
                    }
                )
                attack_id_to_technique_id_map[id_] = group_id

            elif type_ in ("tool", "malware"):
                software_id = _get_attack_id(entry)
                assert software_id.startswith("S")
                values["software"].append(
                    {
                        "name": name_,
                        "original_id": software_id,
                        "description": entry["description"],
                        "id": id_,
                        "type": type_,
                    }
                )
                attack_id_to_technique_id_map[id_] = software_id

            elif type_ == "course-of-action":
                technique_mitigation_id = _get_attack_id(entry)
                if not technique_mitigation_id:
                    continue
                values["technique_mitigation"].append(
                    {
                        "name": name_,
                        "original_id": technique_mitigation_id,
                        "description": entry["description"],
                        "id": id_,
                    }
                )
                attack_id_to_technique_id_map[id_] = technique_mitigation_id

    for entry in data["objects"]:
        if entry["type"] == "relationship":
            if entry["relationship_type"] not in ATTACK_RELATIONSHIP_DATA:
                continue
            if entry.get("x_mitre_deprecated", False) or entry.get("revoked", False):
                logging.info(
                    f"Relationships Revoked or deprecated entry {entry.get('name')} {entry.get('id')}"
                )
                continue

            source = entry["source_ref"]
            target = entry["target_ref"]
            source_id = attack_id_to_technique_id_map.get(source, "")
            target_id = attack_id_to_technique_id_map.get(target, "")
            # TODO do detects mapping as well?
            if entry["relationship_type"] == "mitigates":
                if (
                    source in attack_id_to_technique_id_map.keys()
                    and target in attack_id_to_technique_id_map.keys()
                    and source_id.startswith("M")
                    and target != source
                    and target_id != source_id
                ):
                    values["technique_mitigation_technique_mapping"].append(
                        {
                            "technique_mitigation_id": source_id,
                            "technique_id": target_id,
                        }
                    )

            elif entry["relationship_type"] == "uses":
                source_prefix = source.split("--")[0]
                target_prefix = target.split("--")[0]
                try:
                    src_bron_type = REF_BRON_MAP[source_prefix]
                    tgt_bron_type = REF_BRON_MAP[target_prefix]
                except KeyError as e:
                    logging.warning(f"{e} for {entry}")
                    continue

                key = f"{src_bron_type}_{tgt_bron_type}_mapping"
                if (
                    source in attack_id_to_technique_id_map.keys()
                    and target in attack_id_to_technique_id_map.keys()
                    and target != source
                    and target_id != source_id
                ):
                    values[key].append(
                        {
                            f"{src_bron_type}_id": source_id,
                            f"{tgt_bron_type}_id": target_id,
                        }
                    )

    for key, value in values.items():
        file_path = os.path.join(save_path, f"{key}.jsonl")
        with open(file_path, "w") as fd:
            print(f"Save {fd.name} {len(value)}")
            for line in value:
                json.dump(line, fd)
                fd.write("\n")

        assert os.path.exists(file_path)
        logging.info(f"Parsed ATT&CK data {key} from {file_name} and saved to {file_path}")


def link_technique_technique(file_path: str, save_path: str):
    logging.info(f"Begin linking technique to technique from {file_path}")
    with open(file_path, "r") as fd:
        bundle = stix2.parse(fd, allow_custom=True)

    technique_sub_technique_map = collections.defaultdict(set)
    for object_ in bundle.objects:
        if hasattr(object_, "type") and object_.type == "attack-pattern":
            if hasattr(object_, "x_mitre_is_subtechnique") and object_.x_mitre_is_subtechnique:
                for external_reference in object_.external_references:
                    if external_reference.source_name == "mitre-attack":
                        assert external_reference.external_id.startswith("T")
                        sub_technique = external_reference.external_id
                        parent_technique = sub_technique.split(".")[0]
                        technique_sub_technique_map[parent_technique].add(sub_technique)

    file_path = os.path.join(save_path, "technique_sub_technique_map.json")
    with open(file_path, "w") as fd:
        data_ = dict([(k, list(v)) for k, v in technique_sub_technique_map.items()])
        json.dump(data_, fd, indent=1)

    assert os.path.exists(file_path)
    logging.info(
        f"Done link {len(technique_sub_technique_map)} technique to {sum([len(_) for _ in technique_sub_technique_map.values()])}sub technique to {file_path}"
    )


def parse_attack(file_name: str, save_path: str, domain: str = "mitre-attack", platform: str = ""):
    logging.info(f"Begin parse ATT&CK data from {file_name}")
    # TODO for handling of bronsprak
    # TODO this can be parsed with stix2 library
    ATTACK_DATA = {"attack-pattern", "course-of-action", "x-mitre-tactic"}
    values = collections.defaultdict(list)
    with open(file_name, "r") as fd:
        data = json.load(fd)

    attack_id_to_technique_id_map = {}
    for entry in data["objects"]:
        id_ = entry.get("id", "")
        name_ = entry.get("name", "")
        type_ = entry.get("type", "")
        if type_ in ATTACK_DATA:
            if entry.get("x_mitre_deprecated", False) or entry.get("revoked", False):
                logging.info(
                    f"Mitigations Revoked or deprecated entry {entry.get('name')} {entry.get('id')}"
                )
                continue

            if type_ == "attack-pattern" and entry.get("x_mitre_detection", "") != "":
                domain_str = domain
                # TODO hacky, but also data inconsistent
                if domain == "mitre-mobile-attack":
                    domain_str = "mitre-attack"

                technique_id = _get_attack_id(entry, domain_str)
                if technique_id == "":
                    technique_id = _get_attack_id(entry, domain)

                if technique_id == "":
                    logging.warning(f"No id for {name_}")
                    continue

                category = "x_mitre_detection"
                # TODO this makes no sense, there is no detection information here. Look at "indicators" instead
                values["technique_detection"].append(
                    {
                        "name": name_,
                        "original_id": technique_id,
                        "detection": entry[category],
                        "id": id_,
                    }
                )
                values["technique_detection_technique_mapping"].append(
                    {
                        "technique_detection_id": technique_id,
                        "technique_id": technique_id,
                    }
                )
                attack_id_to_technique_id_map[id_] = technique_id

            if type_ == "attack-pattern":
                domain_str = domain
                # TODO hacky, but also data inconsistent
                if domain == "mitre-mobile-attack":
                    domain_str = "mitre-attack"

                technique_id = _get_attack_id(entry, domain_str)
                if technique_id == "":
                    technique_id = _get_attack_id(entry, domain)

                if technique_id == "":
                    logging.warning(f"No id for {name_}")
                    continue

                data_value = {
                    "name": name_,
                    "original_id": technique_id,
                    "description": entry["description"],
                    "id": id_,
                }
                # TODO do not filter here
                if platform == "cloud":
                    platform_value = entry.get("x_mitre_platforms", "")
                    cloud_platform = any([True for _ in platform_value if _ in CLOUD_PLATFORMS])
                    if cloud_platform:
                        data_value["metadata"] = {"platform": platform_value}
                    else:
                        continue

                values["technique"].append(data_value)
                # TODO very strict in matching
                technique_ics_technique_link = _get_technique_ics_technique_links(entry)
                if technique_ics_technique_link:
                    values["technique_ics_technique_links"].append(technique_ics_technique_link)

                technique_ics_tactic_link = _get_technique_ics_tactic_links(entry, domain)
                if technique_ics_tactic_link:
                    values["technique_tactic_links"].append(
                        {technique_id: technique_ics_tactic_link}
                    )

                attack_id_to_technique_id_map[id_] = technique_id
            elif type_ == "x-mitre-tactic":
                domain_str = domain
                # TODO hacky, but also data inconsistent
                if domain == "mitre-mobile-attack":
                    domain_str = "mitre-attack"

                tactic_id = _get_attack_id(entry, domain_str)
                assert tactic_id.startswith("TA"), f"ID {tactic_id}"
                category = "tactic"
                values["tactic"].append(
                    {
                        "name": name_,
                        "original_id": tactic_id,
                        "description": entry["description"],
                        "id": id_,
                        "shortname": entry["x_mitre_shortname"],
                    }
                )
                attack_id_to_technique_id_map[id_] = tactic_id
            elif type_ == "course-of-action":
                domain_str = domain
                # TODO hacky, but also data inconsistent
                if domain == "mitre-mobile-attack":
                    domain_str = "mitre-attack"

                technique_mitigation_id = _get_attack_mitigation_id(entry, domain_str)
                if not technique_mitigation_id:
                    continue
                values["technique_mitigation"].append(
                    {
                        "name": name_,
                        "original_id": technique_mitigation_id,
                        "description": entry["description"],
                        "id": id_,
                    }
                )
                attack_id_to_technique_id_map[id_] = technique_mitigation_id

    logging.info(f"Relationships to check {len(attack_id_to_technique_id_map)}")
    for entry in data["objects"]:
        if entry.get("x_mitre_deprecated", False) or entry.get("revoked", False):
            logging.info(
                f"Mitigations Relationships Revoked or deprecated entry {entry.get('name')} {entry.get('id')}"
            )
            continue

        if entry["type"] == "relationship":
            if entry["relationship_type"] == "mitigates":

                source = entry["source_ref"]
                target = entry["target_ref"]
                source_id = attack_id_to_technique_id_map.get(source, "")
                target_id = attack_id_to_technique_id_map.get(target, "")
                if (
                    source in attack_id_to_technique_id_map.keys()
                    and target in attack_id_to_technique_id_map.keys()
                    and source_id.startswith("M")
                    and target != source
                    and target_id != source_id
                    and target_id != ""
                ):
                    values["technique_mitigation_technique_mapping"].append(
                        {
                            "technique_mitigation_id": source_id,
                            "technique_id": target_id,
                        }
                    )
                else:
                    logging.info(f"No edge {source} - {target} ({source_id} - {target_id})")

    logging.info(f"Tactic to check {len(values['tactic'])}")
    for key, value in values.items():
        file_path = os.path.join(save_path, f"{key}.jsonl")
        with open(file_path, "w") as fd:
            print(f"Save {fd.name} {len(value)}")
            for line in value:
                json.dump(line, fd)
                fd.write("\n")

        assert os.path.exists(file_path)
        logging.info(f"Parsed ATT&CK data {key} from {file_name} and saved to {file_path}")


if __name__ == "__main__":
    log_file = os.path.basename(__file__).replace(".py", ".log")
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s",
        level=logging.INFO,
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )

    parser = argparse.ArgumentParser(
        description="Parse enterprise-attack.json to get tactic-technique and capec-technique links"
    )
    parser.add_argument(
        "--filename",
        type=str,
        required=True,
        help="File path to raw_enterprise_attack.json",
    )
    parser.add_argument(
        "--save_path", type=str, required=True, help="Folder path to save parsed data"
    )
    parser.add_argument("--mitigations", action="store_true", help="Parse mitigations")
    parser.add_argument(
        "--link_techniques",
        action="store_true",
        help="Link technique and sub-technique",
    )
    args = parser.parse_args()
    if args.mitigations:
        parse_enterprise_attack(args.filename, args.save_path)
        sys.exit(0)
    elif args.link_techniques:
        link_technique_technique(args.filename, args.save_path)
        sys.exit(0)

    link_tactic_techniques(args.filename, args.save_path)
