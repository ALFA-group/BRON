import datetime
import argparse
import os
import json
import sys
import gzip
import shutil
import collections
import tempfile
from typing import Dict

import requests
from pdfminer.high_level import extract_text
from bs4 import BeautifulSoup
from bs4.element import ResultSet
import pandas as pd

import download_threat_information.download_threat_data as BRON_dti
import download_threat_information.parsing_scripts.parse_capec_cwe as BRON_cwe


ATTACK_PATH = "data/bronsprak/csecc_attack.txt"
ATTACK_EXTERNAL_REF_PATH = "data/bronsprak/csecc_attack_external_ref.json"
CWE_EXTERNAL_REF_PATH = "data/bronsprak/csecc_cwe_external_ref.json"
ATTACK_EXTERNAL_REF_INFO_PATH = "data/bronsprak/csecc_attack_external_ref_info.json"
CAPEC_PATH = "data/bronsprak/csecc_capec.txt"
CWE_PATH = "data/bronsprak/csecc_cwe.txt"
CVE_PATH = "data/bronsprak/csecc_cve.txt"
CSECC_PATH = "data/bronsprak/csecc_all.txt"
CSECC_LINKED_PATH = "data/bronsprak/csecc_link_all.txt"
CWE_LINK_ERRORS_PATH = "data/bronsprak/cwe_follow_link_errors.jsonl"
LINK_ERRORS_PATH = "data/bronsprak/follow_link_errors.jsonl"
DO_NOT_FOLLOW_LIST = ("mitre-attack", "capec")
BRON_DATA_DIR = "download_threat_information"


external_ref_info = {}
visited_urls = set()


def get_attack_data(
    data_dir: str, follow_links: bool, test: bool, count_refs_only: bool
):
    if os.path.exists(ATTACK_PATH) and not test:
        print(f"{ATTACK_PATH} EXISTS")
        return

    errors = []
    corpus = collections.defaultdict(list)
    # TODO multi thread for efficiency
    # Parse ATT&CK for text descriptions
    with open(os.path.join(data_dir, BRON_dti.THREAT_DATA_TYPES["ATTACK"]), "r") as fd:
        attack = json.load(fd)
        for entry in attack["objects"]:
            name = entry.get("name", "")
            corpus["attack"].append(name)
            corpus["attack"].append(entry.get("description", ""))
            corpus["attack"].append(entry.get("x_mitre_detection", ""))
            external_ref_info[name] = []
            if follow_links:
                external_references = entry.get("external_references", [])
                for external_reference in external_references:
                    url = external_reference.get("url", "")
                    source_name = external_reference.get("source_name")
                    if url:
                        external_ref_info[name].append(url)
                    if (
                        source_name in DO_NOT_FOLLOW_LIST
                        or not url
                        or url in visited_urls
                        or count_refs_only
                    ):
                        continue
                    if test:
                        print(datetime.datetime.now(), url)
                    link_data = get_link_text(url)
                    link_data["source_name"] = source_name
                    visited_urls.add(url)
                    if link_data.get("response_code", "") != 200:
                        msg = {
                            "name": name,
                            "response-code": link_data["response_code"],
                            "url": url,
                        }
                        errors.append(msg)
                    else:
                        corpus["attack_external_ref"].append(link_data)

    with open(ATTACK_PATH, "w") as fd:
        fd.write(" ".join(corpus["attack"]))

    with open(ATTACK_EXTERNAL_REF_PATH, "w") as fd:
        json.dump(corpus["attack_external_ref"], fd, indent=1)

    with open(ATTACK_EXTERNAL_REF_INFO_PATH, "w") as fd:
        json.dump(external_ref_info, fd, indent=1)

    with open(LINK_ERRORS_PATH, "w") as fd:
        for msg in errors:
            json.dump(msg, fd)
            fd.write("\n")


def get_capec_data(data_dir: str):
    if os.path.exists(CAPEC_PATH):
        print(f"{CAPEC_PATH} EXISTS")
        return

    corpus = collections.defaultdict(list)
    # Parse CAPEC for text descriptions
    with open(os.path.join(data_dir, BRON_dti.THREAT_DATA_TYPES["CAPEC"]), "r") as fd:
        capec = json.load(fd)
        for entry in capec["objects"]:
            corpus["capec"].append(entry.get("name", ""))
            corpus["capec"].append(entry.get("description", ""))
            # TODO use the x_capec_example, x_capec_execution_flow by figuring out how to handle HTML

    with open(CAPEC_PATH, "w") as fd:
        fd.write(" ".join(corpus["capec"].values()))


def get_cwe_data(data_dir: str, follow_links: bool, test: bool):
    if os.path.exists(CWE_PATH) and not test:
        print(f"{CWE_PATH} EXISTS")
        return

    corpus = []
    cwe_file = os.path.join(data_dir, BRON_cwe.CWE_XML_FILE_NAME)
    cwe_data = pd.read_json(cwe_file)
    COLUMNS = [
        "ID",
        "Name",
        "Description",
        "Background Details",
        "Potential Mitigations",
    ]
    for row in cwe_data.iterrows():
        data = row[1][COLUMNS].to_dict()
        for _, value in data.items():
            if type(value) == str:
                corpus.append(value)

    with open(CWE_PATH, "w") as fd:
        fd.write(" ".join(corpus))

    if follow_links:
        cwe_external_ref_file = os.path.join(
            data_dir, BRON_cwe.CWE_EXTERNAL_REF_FILE_NAME
        )
        with open(cwe_external_ref_file, "r") as fd:
            data = json.load(fd)

        corpus = []
        errors = []
        for url in data:
            if url in visited_urls:
                continue
            if test:
                print(datetime.datetime.now(), url)
            link_data = get_link_text(url)
            link_data["source_name"] = "CWE"
            visited_urls.add(url)
            if link_data.get("response_code", "") != 200:
                msg = {
                    "name": "CWE",
                    "response-code": link_data["response_code"],
                    "url": url,
                }
                errors.append(msg)
            else:
                corpus.append(link_data)

        with open(CWE_EXTERNAL_REF_PATH, "w") as fd:
            json.dump(corpus, fd, indent=1)

        with open(CWE_LINK_ERRORS_PATH, "w") as fd:
            for msg in errors:
                json.dump(msg, fd)
                fd.write("\n")


def get_cve_data(data_dir: str):
    if os.path.exists(CVE_PATH):
        print(f"{CVE_PATH} EXISTS")
        return

    cve_file = os.path.join(data_dir, BRON_dti.THREAT_DATA_TYPES["CVE"])
    corpus = []
    with gzip.open(cve_file, "rt", encoding="utf-8") as f:
        cve_data = json.load(f)
        for item in cve_data["CVE_Items"]:
            corpus.append(f'{item["cve"]["CVE_data_meta"]["ID"]}:')
            corpus.append(item["cve"]["description"]["description_data"][0]["value"])

    with open(CVE_PATH, "w") as fd:
        fd.write(" ".join(corpus))


def get_bron_data(
    follow_links: bool = False, test: bool = False, count_refs_only: bool = False
):
    # TODO smoother BRON integration/ Refactor corpus generation to BRON (it is more of a BRON responsibility)
    # Run python download_threat_information/download_threat_data.py from BRON
    data_dir = BRON_DATA_DIR
    get_attack_data(data_dir, follow_links, test, count_refs_only)
    get_capec_data(data_dir)
    get_cwe_data(data_dir, follow_links, test)
    get_cve_data(data_dir)

    # TODO add d3fend


def concatenate_files():
    if os.path.exists(CSECC_PATH):
        print(f"{CSECC_PATH} EXISTS")
        return

    dir_ = "data/bronsprak/"
    with open(CSECC_PATH, "wb") as out_fd:
        for file_ in os.listdir(dir_):
            if file_ in CSECC_PATH:
                continue
            if file_.startswith("csecc"):
                print(f"COPY {file_}")
                with open(os.path.join(dir_, file_), "rb") as fd:
                    shutil.copyfileobj(fd, out_fd)


def get_link_text(url: str) -> Dict[str, str]:
    # TODO not really an accurate response code
    result = {"text": "", "url": url, "response_code": 666, "error": ""}
    try:
        response = requests.get(url, timeout=5)
    except Exception as e:
        result["error"] = str(e)
        return result

    # TODO use tmpfile module
    text = ""
    result["response_code"] = int(response.status_code)
    result["reason"] = str(response.reason)
    result["apparent_encoding"] = str(response.apparent_encoding)
    result["encoding"] = str(response.encoding)
    try:
        if "pdf" in response.headers.get("Content-Type", ""):
            with tempfile.NamedTemporaryFile() as f:
                f.write(response.content)
                text = extract_text(f.name)

        else:
            html_text = response.text
            # TODO do not get header and footer part
            soup = BeautifulSoup(html_text, "html.parser")
            # TODO Filter text
            text = ""
            text += soup.find_all("body")
            text += soup.find_all("main")
    except Exception as e:
        result["error"] = str(e)
        return result

    result["text"] = text

    return result


def _concatenate_linked_files():
    shutil.copyfile(CSECC_PATH, CSECC_LINKED_PATH)
    with open(ATTACK_EXTERNAL_REF_PATH, "r") as fd:
        data = json.load(fd)

    ed_data = []
    with open(CSECC_LINKED_PATH, "w") as fd:
        for document in data:
            if (
                document["response_code"] != 200
                or document["source_name"] in DO_NOT_FOLLOW_LIST
            ):
                continue

            text = document["text"].split()
            fd.write(text)
            ed_data.append(document)

    with open("data/bronsprak/csecc_attack_external_ref_ed.json", "w") as fd:
        json.dump(ed_data, fd, indent=1)


def main(args):
    if not args["concatenate_files"]:
        # TODO crawl links in BRON data (i.e. refernces in ATT&CK and CVE)
        get_bron_data(args["follow_links"], args["test"], args["count_refs_only"])

    # Make one file
    concatenate_files()
    if args["follow_links"]:
        _concatenate_linked_files()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Gather cyber security language corpus from BRON"
    )
    parser.add_argument(
        "--follow_links",
        action="store_true",
        help="Follow links in BRON sources",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Test settings, i.e. reduced traning settings",
    )
    parser.add_argument(
        "--count_refs_only",
        action="store_true",
        help="Do not follow external references",
    )
    parser.add_argument(
        "--concatenate_files",
        action="store_true",
        help="Concatenate the files to a single file",
    )
    parser.add_argument(
        "--test_cwe",
        action="store_true",
        help="Test CWE",
    )
    # TOOD save as a JSON with source as the key
    args_ = vars(parser.parse_args(sys.argv[1:]))
    corpus_path = "data/bronsprak/corpus/"
    if args_["test_cwe"]:
        get_cwe_data(BRON_DATA_DIR, follow_links=True, test=True)
        sys.exit(0)

    main(args_)
