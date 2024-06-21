import argparse
import os
import json
import datetime
import hashlib
import gzip
import shutil
import sys
import logging

import requests


# TODO how to check if there are updates, or different URLs
# TODO add some verbosity

ENTERPRISE_ATTACK_URL = (
    "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"
)
CAPEC_URL = "https://github.com/mitre/cti/raw/master/capec/2.1/stix-capec.json"
CAPEC_XML_URL = "http://capec.mitre.org/data/xml/capec_latest.xml"
# TODO are there better CAPEC views?
CWE_XML_URL = "http://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CVE_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1"
LAST_YEAR = datetime.datetime.now().year + 1
FIRST_YEAR = 2002
RECENT_OFFSET = 1
CVE_ALL_YEARS = list(map(str, range(FIRST_YEAR, LAST_YEAR)))
CVE_RECENT_YEARS = list(map(str, range(LAST_YEAR - RECENT_OFFSET, LAST_YEAR)))

OUTPUT_FOLDER = "data/raw"
THREAT_DATA_TYPES = {
    "ATTACK": "raw_enterprise_attack.json",
    "CAPEC": "raw_CAPEC.json",
    "CAPEC_XML": "raw_CAPEC.xml",
    "CWE": "raw_CWE.zip",
    "CWE_XML": "raw_CWE_xml.zip",
    "CVE": "raw_CVE.json.gz",
}
BRON_META_DATA_PATH = "bron_meta_data.json"


def _write_meta_data(threat_data_type: str, file_path: str) -> None:
    meta_data_path = os.path.join(OUTPUT_FOLDER, BRON_META_DATA_PATH)
    try:
        with open(meta_data_path, "r") as fd:
            meta_data = json.load(fd)
    except FileNotFoundError:
        meta_data = {}

    _t = datetime.datetime.now(datetime.timezone.utc)
    # TODO not super efficient to reread file to get checksum
    _md5 = md5(file_path)
    data_info = {
        "timestamp": _t.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "file_path": file_path,
        "md5_checksum": _md5,
    }
    meta_data[threat_data_type] = data_info

    with open(meta_data_path, "w") as fd:
        json.dump(meta_data, fd, indent=4)

    assert os.path.exists(meta_data_path)


def md5(file_path: str) -> str:
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)

    return hash_md5.hexdigest()


def _download_attack():
    response = requests.get(ENTERPRISE_ATTACK_URL)
    file_path = os.path.join(OUTPUT_FOLDER, THREAT_DATA_TYPES["ATTACK"])
    with open(file_path, "w") as fd:
        json.dump(response.json(), fd)

    # TODO make sure to remove file before for this assert to be meaningful (or assert timestamps)
    assert os.path.exists(file_path)
    _write_meta_data(threat_data_type="ATTACK", file_path=file_path)
    logging.info(f"Downloaded ATT&CK from {ENTERPRISE_ATTACK_URL} to {file_path}")


def _download_capec_xml():
    response = requests.get(CAPEC_XML_URL, stream=True)
    file_path = os.path.join(OUTPUT_FOLDER, THREAT_DATA_TYPES["CAPEC_XML"])
    with open(file_path, "wb") as fd:
        for chunk in response.iter_content(chunk_size=128):
            fd.write(chunk)

    assert os.path.exists(file_path)
    _write_meta_data(threat_data_type="CAPEC_XML", file_path=file_path)
    logging.info(f"Downloaded CAPECs from {CAPEC_XML_URL} to {file_path}")


def _download_cwe_xml():
    response = requests.get(CWE_XML_URL, stream=True)
    file_path = os.path.join(OUTPUT_FOLDER, THREAT_DATA_TYPES["CWE_XML"])
    with open(file_path, "wb") as fd:
        for chunk in response.iter_content(chunk_size=128):
            fd.write(chunk)

    assert os.path.exists(file_path)
    _write_meta_data(threat_data_type="CWE_XML", file_path=file_path)
    logging.info(f"Downloaded CWEs from {CWE_XML_URL} to {file_path}")


def _download_cve(cve_years):
    combined_cve = {"CVE_Items": []}
    for year in cve_years:
        # Download CVE data for each year
        cve_url = os.path.join(CVE_BASE_URL, f"nvdcve-1.1-{year}.json.gz")
        response = requests.get(cve_url, stream=True)
        year_file_path = os.path.join(OUTPUT_FOLDER, f"raw_CVE_{year}.json.gz")
        with open(year_file_path, "wb") as fd:
            for chunk in response.iter_content(chunk_size=128):
                fd.write(chunk)

        # Combine CVE data into one json.gz file
        cve_path = os.path.join(OUTPUT_FOLDER, f"raw_CVE_{year}.json.gz")
        with gzip.open(cve_path, "rt", encoding="utf-8") as f:
            cve_data = json.load(f)
        combined_cve["CVE_Items"].extend(cve_data["CVE_Items"])
    json_string = json.dumps(combined_cve)
    encoded = json_string.encode("utf-8")
    file_path = os.path.join(OUTPUT_FOLDER, THREAT_DATA_TYPES["CVE"])
    with gzip.GzipFile(file_path, "w") as f:
        f.write(encoded)

    assert os.path.exists(file_path)
    _write_meta_data(threat_data_type="CVE", file_path=file_path)
    logging.info(f"Downloaded CVEs from {CVE_BASE_URL} for {cve_years} to {file_path}")


def main(cve_years) -> None:
    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)
        logging.info(f"Created {OUTPUT_FOLDER}")

    _download_attack()
    _download_capec_xml()
    _download_cwe_xml()
    _download_cve(cve_years)


def clean():
    try:
        shutil.rmtree(OUTPUT_FOLDER)
    except FileNotFoundError:
        pass

    os.makedirs(OUTPUT_FOLDER)
    logging.info(f"Cleaned {OUTPUT_FOLDER}")


if __name__ == "__main__":
    log_file = os.path.basename(__file__).replace(".py", ".log")
    logging.basicConfig(
        format="%(asctime)s %(levelname)s: %(message)s",
        level=logging.INFO,
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )
    parser = argparse.ArgumentParser(description="Download raw data for BRON")
    parser.add_argument(
        "--threat_data_type",
        type=str,
        choices=list(THREAT_DATA_TYPES.keys()),
        help="Download only one threat data type, e.g threat-data-type=CVE",
    )
    parser.add_argument(
        "--only_recent_cves",
        action="store_true",
        help="For CVEs, add argument to download only recent CVE data from 2015-2020",
    )
    parser.add_argument("--clean", action="store_true", help="Clean all files")
    args = parser.parse_args()
    only_recent_cves = args.only_recent_cves
    if args.clean:
        clean()
        sys.exit(0)

    if only_recent_cves:
        cve_years_ = CVE_RECENT_YEARS
    else:
        cve_years_ = CVE_ALL_YEARS
    if args.threat_data_type:
        if args.threat_data_type == "ATTACK":
            _download_attack()
        elif args.threat_data_type == "CAPEC":
            _download_capec_xml()
        elif args.threat_data_type == "CWE":
            _download_cwe_xml()
        elif args.threat_data_type == "CVE":
            _download_cve(cve_years_)
        else:
            raise Exception(f"Bad threat data type: {args.threat_data_type}")
    else:
        main(cve_years_)
