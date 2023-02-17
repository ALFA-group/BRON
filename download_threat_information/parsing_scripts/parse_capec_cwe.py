import collections
import logging
import json
import zipfile
import os
import argparse
import xml.etree.ElementTree as Xet

import pandas as pd


CWE_XML_FILE_NAME = "cwe_from_xml.json"
CWE_EXTERNAL_REF_FILE_NAME = "cwe_external_references.json"
CWE_CWE_LINK_FILE_NAME = "cwe_cwe_map.json"
CAPEC_XML_FILE_NAME = "capec_from_xml.json"
CAPEC_EXTERNAL_REF_FILE_NAME = "capec_external_references.json"
CAPEC_CAPEC_LINK_FILE_NAME = "capec_capec_map.json"


def parse_capec_xml_to_csv(capec_xml_file: str, save_path: str) -> None:
    logging.info(f"Begin parse CAPEC {capec_xml_file}")
    data = {"Attack Patterns": [], "External References": set()}
    internal_links = collections.defaultdict(set)
    ns = {"capec-3": "http://capec.mitre.org/capec-3"}
    # Parsing the XML file
    xmlparse = Xet.parse(capec_xml_file)
    root = xmlparse.getroot()
    els = root.findall("./capec-3:Attack_Patterns/capec-3:Attack_Pattern", ns)
    for el in els:
        if el.attrib["Status"] == "Deprecated":
            logging.info(f"Deprecated CAPEC entry {el.attrib['ID']} {el.attrib['Name']}")
            continue

        # TODO read from schema
        values = {
            "ID": el.attrib["ID"],
            "Name": el.attrib["Name"],
            "Mitigations": [],
            "Indicators": [],
            "Related_Weaknesses": [],
            "Taxonomy_Mappings": [],
            "Likelihood of Attack": "",
            "Typical Severity": "",
            "Prerequisites": [],
            "Skills Required": [],
            "Resources Required": [],
            "Consequences": [],
        }
        data["Attack Patterns"].append(values)
        d = el.findtext("./capec-3:Description", default="", namespaces=ns)
        values["Description"] = d
        d = el.findtext("./capec-3:Extended_Description", default="", namespaces=ns)
        values["Extended_Description"] = d
        # TODO more text to get to bronsprak from CAPEC XML
        ms = el.findall("./capec-3:Mitigations/capec-3:Mitigation", ns)
        for m in ms:
            text = "".join(m.itertext())
            if text:
                values["Mitigations"].append(text)

        ms = el.findall("./capec-3:Indicators/capec-3:Indicator", ns)
        for m in ms:
            text = "".join(m.itertext())
            if text:
                values["Indicators"].append(text)

        ms = el.findall("./capec-3:Related_Weaknesses/capec-3:Related_Weakness", ns)
        for m in ms:
            values["Related_Weaknesses"].append(m.get("CWE_ID"))

        ms = el.findall("./capec-3:Taxonomy_Mappings/capec-3:Taxonomy_Mapping", ns)
        for m in ms:
            match = m.find("./capec-3:Entry_ID", ns)
            # TODO check that it is ATT&CK
            if match is not None:
                values["Taxonomy_Mappings"].append(match.text)

        # TODO the CanPrecede relation (this is difficult in a property graph, but more useful in a knowledge graph)
        # Related Attack Patterns
        ms = el.findall("./capec-3:Related_Attack_Patterns/capec-3:Related_Attack_Pattern", ns)
        for m in ms:
            nature = m.attrib["Nature"]
            if nature in ("ChildOf", "ParentOf"):
                if nature == "ChildOf":
                    internal_links[m.attrib["CAPEC_ID"]].add(el.attrib["ID"])
                else:
                    internal_links[el.attrib["ID"]].add(m.attrib["CAPEC_ID"])

        ds = el.findall("./capec-3:Prerequisites/capec-3:Prerequisite", ns)
        for d in ds:
            values["Prerequisites"].append(d.text.strip())

        ds = el.find("./capec-3:Likelihood_Of_Attack", ns)
        values["Likelihood of Attack"] = ds.text if ds is not None else ""

        ds = el.find("./capec-3:Typical_Severity", ns)
        values["Typical Severity"] = ds.text if ds is not None else ""

        ds = el.findall("./capec-3:Skills_Required/capec-3:Skill", ns)
        for d in ds:
            level = d.attrib["Level"]
            values["Skills Required"].append(
                {"level": level, "skill": d.text.strip() if d.text is not None else ""}
            )

        ds = el.findall("./capec-3:Resources_Required/capec-3:Resource", ns)
        for d in ds:
            values["Resources Required"].append(d.text.strip() if d.text is not None else "")

        ds = el.findall("./capec-3:Consequences/capec-3:Consequence", ns)
        for d in ds:
            info = {}
            values["Consequences"].append(info)
            for t in d:
                key = _remove_namespace(t.tag, ns["capec-3"])
                info[key] = t.text

    file_name = os.path.join(save_path, CAPEC_XML_FILE_NAME)
    with open(file_name, "w") as fd:
        json.dump(data["Attack Patterns"], fd, indent=1)

    assert os.path.exists(file_name)

    els = root.findall("./capec-3:External_References/capec-3:External_Reference/capec-3:URL", ns)
    for el in els:
        text = el.text
        if text is not None and text.strip():
            data["External References"].add(text.strip())

    file_name = os.path.join(save_path, CAPEC_EXTERNAL_REF_FILE_NAME)
    with open(file_name, "w") as fd:
        json.dump(list(data["External References"]), fd, indent=1)

    assert os.path.exists(file_name)

    file_name = os.path.join(save_path, CAPEC_CAPEC_LINK_FILE_NAME)
    with open(file_name, "w") as fd:
        data_ = dict([(k, list(v)) for k, v in internal_links.items()])
        json.dump(data_, fd, indent=1)

    logging.info(f"Parsd CAPEC {capec_xml_file} to {save_path}")


def _remove_namespace(tag: str, namespace: str) -> str:
    # TODO faster or built in fcn?
    n_ns = len(namespace) + 2  # {} are added
    return tag[n_ns:]


def parse_cwe_xml_to_csv(cwe_file: str, save_path: str, download_path: str) -> None:
    logging.info(f"Begin parse CWE {cwe_file}")
    with zipfile.ZipFile(cwe_file) as fd:
        files = fd.namelist()
        assert len(files) == 1
        fd.extractall(download_path)

    cwe_xml_file = os.path.join(download_path, files[0])
    internal_links = collections.defaultdict(set)
    data = {"Weaknesses": [], "External References": set()}
    ns = {"cwe-6": "http://cwe.mitre.org/cwe-6"}
    INFO = {
        "Mitigation": ("Phase", "Description"),
        "Detection": ("Method", "Description"),
    }
    # Parsing the XML file
    xmlparse = Xet.parse(cwe_xml_file)
    root = xmlparse.getroot()
    els = root.findall("./cwe-6:Weaknesses/cwe-6:Weakness", ns)
    for el in els:
        if el.attrib["Status"] == "Deprecated":
            logging.info(f"Deprecated CWE entry {el.attrib['ID']} {el.attrib['Name']}")
            continue

        values = {
            "ID": el.attrib["ID"],
            "Name": el.attrib["Name"],
            "Potential Mitigations": [],
            "Detection Methods": [],
            "Applicable Platforms": [],
            "Likelihood of Exploit": "",
            "Common Consequences": [],
        }
        data["Weaknesses"].append(values)
        # TODO use findtext
        d = el.find("./cwe-6:Description", ns)
        values["Description"] = d.text if d is not None else ""
        d = el.find("./cwe-6:Extended_Description", ns)
        values["Extended_Description"] = d.text if d is not None else ""
        ds = el.findall("./cwe-6:Background_Details/cwe-6:Background_Detail", ns)
        values["Background Details"] = ""
        if ds:
            values["Background Details"] = "\n".join([_.text.strip() for _ in ds])

        ms = el.findall("./cwe-6:Potential_Mitigations/cwe-6:Mitigation", ns)
        for m in ms:
            info = {"Phase": "NA"}
            for tag in INFO["Mitigation"]:
                match = m.find(f"./cwe-6:{tag}", namespaces=ns)
                if match is not None:
                    if tag == "Description":
                        text = "".join(match.itertext())
                    else:
                        text = match.text
                    info[tag] = text

            if info:
                assert len(info) == len(INFO["Mitigation"])
                values["Potential Mitigations"].append(info)

        ms = el.findall("./cwe-6:Detection_Methods/cwe-6:Detection_Method", ns)
        for m in ms:
            info = {}
            for tag in INFO["Detection"]:
                match = m.find(f"./cwe-6:{tag}", namespaces=ns)
                if match is not None:
                    if tag == "Description":
                        text = "".join(match.itertext())
                    else:
                        text = match.text
                    info[tag] = text

            if info:
                assert len(info) == len(INFO["Detection"])
                values["Detection Methods"].append(info)

        # Related Attack Patterns
        ms = el.findall("./cwe-6:Related_Weaknesses/cwe-6:Related_Weakness", ns)
        for m in ms:
            nature = m.attrib["Nature"]
            if nature in ("ChildOf", "ParentOf"):
                if nature == "ChildOf":
                    internal_links[m.attrib["CWE_ID"]].add(el.attrib["ID"])
                else:
                    internal_links[el.attrib["ID"]].add(m.attrib["CWE_ID"])

        ds = el.findall("./cwe-6:Applicable_Platforms/cwe-6:Language", ns)
        values["Applicable Platforms"] = [_.attrib["Class"] for _ in ds if "Class" in _.attrib]

        ds = el.findall("./cwe-6:Common_Consequences/cwe-6:Consequence", ns)
        for d in ds:
            info = {}
            values["Common Consequences"].append(info)
            for t in d:
                key = _remove_namespace(t.tag, ns["cwe-6"])
                info[key] = t.text

        ds = el.find("./cwe-6:Likelihood_Of_Exploit", ns)
        values["Likelihood of Exploit"] = ds.text if ds is not None else ""

    file_name = os.path.join(save_path, CWE_XML_FILE_NAME)
    with open(file_name, "w") as fd:
        json.dump(data["Weaknesses"], fd, indent=1)

    assert os.path.exists(file_name)

    els = root.findall("./cwe-6:External_References/cwe-6:External_Reference/cwe-6:URL", ns)
    for el in els:
        text = el.text
        if text is not None and text.strip():
            data["External References"].add(text.strip())

    file_name = os.path.join(save_path, CWE_EXTERNAL_REF_FILE_NAME)
    with open(file_name, "w") as fd:
        json.dump(list(data["External References"]), fd, indent=1)

    assert os.path.exists(file_name)

    file_name = os.path.join(save_path, CWE_CWE_LINK_FILE_NAME)
    with open(file_name, "w") as fd:
        data_ = dict([(k, list(v)) for k, v in internal_links.items()])
        json.dump(data_, fd, indent=1)

    logging.info(f"Parsed {cwe_file} to {save_path}")


def _load_cwe_file(save_path: str) -> "DataFrame":
    file_name = os.path.join(save_path, CWE_XML_FILE_NAME)
    with open(file_name, "r") as fd:
        cwe_data = pd.read_json(fd)

    return cwe_data


def _load_capec_file(save_path: str) -> "DataFrame":
    file_name = os.path.join(save_path, CAPEC_XML_FILE_NAME)
    with open(file_name, "r") as fd:
        capec_data = pd.read_json(fd)

    return capec_data


def parse_capec_cwe_files(save_path):
    logging.info(f"Begin parse CAPEC and CWE connections")
    # Create dictionaries for parsed data
    data = {
        "capec_names": {},
        "cwe_names": {},
        "capec_descriptions": {},
        "cwe_descriptions": {},
        "capec_cwe_mapping": {"capec_cwe": dict()},
    }

    # Load CAPEC and CWE data
    capec_objects = _load_capec_file(save_path)
    cwe_data = _load_cwe_file(save_path)
    # Make capec_names_dict
    for row in capec_objects.iterrows():
        capec_entry = row[1]
        capec_id = capec_entry["ID"]
        capec_name = capec_entry["Name"]
        data["capec_names"][capec_id] = capec_name
        data["capec_descriptions"][capec_id] = {
            "short_description": capec_entry["Description"],
            "description": capec_entry["Extended_Description"],
            "likelihood_of_attack": capec_entry["Likelihood of Attack"],
            "typical_severity": capec_entry["Typical Severity"],
            "skills_required": capec_entry["Skills Required"],
            "resources_required": capec_entry["Resources Required"],
            "consequences": capec_entry["Consequences"],
        }

    # Make cwe_names_dict
    for _, row in cwe_data[
        [
            "ID",
            "Name",
            "Description",
            "Extended_Description",
            "Applicable Platforms",
            "Common Consequences",
            "Likelihood of Exploit",
        ]
    ].iterrows():
        cwe_id = str(row["ID"])
        data["cwe_names"][cwe_id] = row["Name"]
        data["cwe_descriptions"][cwe_id] = {
            "short_description": row["Description"],
            "description": row["Extended_Description"],
            "applicable_platform": row["Applicable Platforms"],
            "common_consequences": row["Common Consequences"],
            "likeliehood_of_exploit": row["Likelihood of Exploit"],
        }

    # Make capec_cwe_mapping_dict
    for row in capec_objects.iterrows():
        capec_entry = row[1]
        if capec_entry["Related_Weaknesses"]:
            capec_cwes = capec_entry["Related_Weaknesses"]
            capec_id = capec_entry["ID"]
            # TODO data sources seem to have more bidirectional links
            # TODO why is this structure seemingly more complex than needed?
            data["capec_cwe_mapping"]["capec_cwe"][capec_id] = {"cwes": capec_cwes}

    # TODO Now capec has Technique mapping add that as well (and OWASP)
    # Save parsed data
    for key, values in data.items():
        file_name = os.path.join(save_path, f"{key}.json")
        with open(file_name, "w") as fd:
            fd.write(json.dumps(values, indent=4, sort_keys=True))

        assert os.path.exists(file_name)
        logging.info(f"Parsed and saved {key} to {file_name}")


if __name__ == "__main__":
    log_file = os.path.basename(__file__).replace(".py", ".log")
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s",
        level=logging.INFO,
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )

    parser = argparse.ArgumentParser(description="Parse raw_CAPEC.json and raw_CWE.zip")
    parser.add_argument("--capec_file", type=str, required=True, help="File path to raw_CAPEC.json")
    parser.add_argument("--cwe_file", type=str, required=True, help="File path to raw_CWE.zip")
    parser.add_argument(
        "--save_path", type=str, required=True, help="Folder path to save parsed data"
    )
    parser.add_argument(
        "--download_path",
        type=str,
        required=True,
        help="Folder path to downloaded data",
    )
    args = parser.parse_args()
    capec_file_ = args.capec_file
    cwe_file_ = args.cwe_file
    save_path_ = args.save_path
    parse_capec_xml_to_csv(capec_file_, save_path_)
    parse_cwe_xml_to_csv(cwe_file_, save_path_, args.download_path)
    parse_capec_cwe_files(save_path_)
