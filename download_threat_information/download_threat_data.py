import argparse
import os
import json
import datetime
import hashlib
import requests
import gzip

# TODO how to check if there are updates, or different URLs
# TODO add some verbosity

ENTERPRISE_ATTACK_URL = 'https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json'
CAPEC_URL = 'https://github.com/mitre/cti/raw/master/capec/2.1/stix-capec.json'
CWE_URL = 'https://cwe.mitre.org/data/csv/1000.csv.zip'
CVE_BASE_URL = 'https://nvd.nist.gov/feeds/json/cve/1.1'
LAST_YEAR = 2021
FIRST_YEAR = 2002
RECENT_OFFSET = 5
CVE_ALL_YEARS = list(map(str, range(FIRST_YEAR, LAST_YEAR)))
CVE_RECENT_YEARS = list(map(str, range(LAST_YEAR - RECENT_OFFSET, LAST_YEAR)))

OUTPUT_FOLDER = 'download_threat_information'
THREAT_DATA_TYPES = {
    'ATTACK': 'raw_enterprise_attack.json',
    'CAPEC': 'raw_CAPEC.json',
    'CWE': 'raw_CWE.zip',
    'CVE': 'raw_CVE.json.gz',
}
BRON_META_DATA_PATH = 'bron_meta_data.json'


def _write_meta_data(threat_data_type: str, file_path: str) -> None:
    meta_data_path = os.path.join(OUTPUT_FOLDER, BRON_META_DATA_PATH)
    try:
        with open(meta_data_path, 'r') as fd:
            meta_data = json.load(fd)
    except FileNotFoundError:
        meta_data = {}

    _t = datetime.datetime.now(datetime.timezone.utc)
    # TODO not super efficient to reread file to get checksum
    _md5 = md5(file_path)
    data_info = {'timestamp': _t.strftime("%Y-%m-%d %H:%M:%S %Z"),
                 'file_path': file_path,
                 'md5_checksum': _md5
                 }
    meta_data[threat_data_type] = data_info

    with open(meta_data_path, 'w') as fd:
        json.dump(meta_data, fd, indent=4)


def md5(file_path: str) -> str:
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def _download_attack():
    response = requests.get(ENTERPRISE_ATTACK_URL)
    file_path = os.path.join(OUTPUT_FOLDER, THREAT_DATA_TYPES['ATTACK'])
    with open(file_path, 'w') as fd:
        json.dump(response.json(), fd)

    # TODO make sure to remove file before for this assert to be meaningful (or assert timestamps)
    assert os.path.exists(file_path)
    _write_meta_data(threat_data_type='ATTACK', file_path=file_path)


def _download_capec():
    response = requests.get(CAPEC_URL)
    file_path = os.path.join(OUTPUT_FOLDER, THREAT_DATA_TYPES['CAPEC'])
    with open(file_path, 'w') as fd:
        json.dump(response.json(), fd, indent=4)

    assert os.path.exists(file_path)
    _write_meta_data(threat_data_type='CAPEC', file_path=file_path)


def _download_cwe():
    response = requests.get(CWE_URL, stream=True)
    file_path = os.path.join(OUTPUT_FOLDER, THREAT_DATA_TYPES['CWE'])
    with open(file_path, 'wb') as fd:
        for chunk in response.iter_content(chunk_size=128):
            fd.write(chunk)

    assert os.path.exists(file_path)
    _write_meta_data(threat_data_type='CWE', file_path=file_path)


def _download_cve(cve_years):
    combined_cve = {'CVE_Items': []}
    for year in cve_years:
        # Download CVE data for each year
        cve_url = os.path.join(CVE_BASE_URL, f"nvdcve-1.1-{year}.json.gz")
        response = requests.get(cve_url, stream=True)
        year_file_path = os.path.join(OUTPUT_FOLDER, f"raw_CVE_{year}.json.gz")
        with open(year_file_path, 'wb') as fd:
            for chunk in response.iter_content(chunk_size=128):
                fd.write(chunk)

        # Combine CVE data into one json.gz file
        cve_path = os.path.join(OUTPUT_FOLDER, f"raw_CVE_{year}.json.gz")
        with gzip.open(cve_path, "rt", encoding="utf-8") as f:
            cve_data = json.load(f)
        combined_cve['CVE_Items'].extend(cve_data['CVE_Items'])
    json_string = json.dumps(combined_cve)
    encoded = json_string.encode('utf-8')
    file_path = os.path.join(OUTPUT_FOLDER, THREAT_DATA_TYPES['CVE'])
    with gzip.GzipFile(file_path, 'w') as f:
        f.write(encoded)

    assert os.path.exists(file_path)
    _write_meta_data(threat_data_type='CVE', file_path=file_path)


def main(cve_years, out_path=None) -> None:
    global OUTPUT_FOLDER
    if out_path:
        OUTPUT_FOLDER = out_path
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)
    _download_attack()
    _download_capec()
    _download_cwe()
    _download_cve(cve_years)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Download raw data for BRON")
    parser.add_argument(
        "--threat_data_type",
        type=str,
        choices=list(THREAT_DATA_TYPES.keys()),
        help="Download only one threat data type, e.g threat-data-type=CVE",
    )
    parser.add_argument(
        "--only_recent_cves",
        action='store_true',
        help="For CVEs, add argument to download only recent CVE data from 2015-2020"
    )
    args = parser.parse_args()
    only_recent_cves = args.only_recent_cves
    if only_recent_cves:
        cve_years = CVE_RECENT_YEARS
    else:
        cve_years = CVE_ALL_YEARS
    if args.threat_data_type:
        if args.threat_data_type == 'ATTACK':
            _download_attack()
        elif args.threat_data_type == 'CAPEC':
            _download_capec()
        elif args.threat_data_type == 'CWE':
            _download_cwe()
        elif args.threat_data_type == 'CVE':
            _download_cve(cve_years)
        else:
            raise Exception(f'Bad threat data type: {args.threat_data_type}')
    else:
        main(cve_years)
