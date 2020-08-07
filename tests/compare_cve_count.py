import json
import argparse


def year_to_count(all_cves):
    """
    cve_dict (dict or set): contains CVE IDs

    Returns dict mapping years to number of CVEs from that year in cve_dict
    """
    year_to_count = dict()

    for cve_id in all_cves:
        year = cve_id[4:8] # cve_id is in the form of "CVE-year-"
        if year not in year_to_count:
            year_to_count[year] = 0
        year_to_count[year] += 1

    return year_to_count


def _add_cves(cve_file):
    original_cve_ids = set()
    all_cves = cve_file['CVE_Items']
    for cve in all_cves:
        cve_id = cve["cve"]["CVE_data_meta"]["ID"]
        original_cve_ids.add(cve_id)

    return original_cve_ids

def count_cves_by_year(cve_path, parsed_path):
    """
    cve_path (str): file path to combined CVEs

    Returns dict mapping year (str) to number of CVEs (int) for original and parsed CVE files
    """
    with open(cve_path) as f:
        cve_file = json.load(f)
    with open(parsed_path) as f:
        parsed_file = json.load(f)

    original_cve_ids = _add_cves(cve_file)

    year_count_original = year_to_count(original_cve_ids)
    year_count_parsed = year_to_count(parsed_file)
    print("Original CVE: ", year_count_original, "\nParsed CVE: ", year_count_parsed)

    total_original_cves = sum(year_count_original.values())
    total_parsed_cves = sum(year_count_parsed.values())
    print("Total CVEs for original and parsed: ", total_original_cves, total_parsed_cves)


def cve_id_set_diff(cve_path, parsed_path):
    """
    Returns set difference of CVE IDs that are in the original but not parsed file
    """
    with open(cve_path) as f:
        cve_file = json.load(f)
    with open(parsed_path) as f:
        parsed_file = json.load(f)

    original_ids = _add_cves(cve_file)

    parsed_ids = set(parsed_file.keys())
    set_diff = original_ids.difference(parsed_ids)
    print(set_diff, len(set_diff))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compare number of CVEs by year between original and parsed CVE files")
    parser.add_argument(
        "--cve_path", type=str, required=True, help="Location of original CVE data as JSON file"
    )
    parser.add_argument(
        "--parsed_path", type=str, required=True, help="Location of parsed CVE data as JSON file"
    )
    parser.add_argument(
        "--cve_id_diff", action='store_true', help="Look at set difference of CVE IDs for original and parsed files"
    )
    args = parser.parse_args()
    cve_path = args.cve_path
    parsed_path = args.parsed_path
    cve_id_diff = False
    cve_id_diff = args.cve_id_diff
    if cve_id_diff:
        cve_id_set_diff(cve_path, parsed_path)
    else:
        count_cves_by_year(cve_path, parsed_path)
