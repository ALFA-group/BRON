import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import argparse
import os
import sys
from typing import List, Dict, Any

"""
Count connections between data types
"""

def count_contents(data_summary_folder, all_versions, all_years):
    if all_versions and all_years:
        FILE_PATH = 'all_cves_all_versions'
    if all_versions and not all_years:
        FILE_PATH = 'recent_cves_all_versions'
    if not all_versions and all_years:
        FILE_PATH = 'all_cves_latest_version'
    if not all_versions and not all_years:
        FILE_PATH = 'recent_cves_latest_version'
    TOTAL_FILE_PATH = os.path.join(data_summary_folder, FILE_PATH)
    neighbor_dict = {'tactic': ['technique'], 'technique': ['tactic', 'capec'], 'capec': ['technique', 'cwe'],
                     'cwe': ['capec', 'cve'], 'cve': ['cwe', 'cpe'], 'cpe': ['cve']}
    node_keys = ("floating", "above_only", "below_only", "both")
    dict_neighbor_dict = {}
    for level in neighbor_dict.keys():
        dict_neighbor_dict[level] = dict([(k, 0) for k in node_keys])
    for key in neighbor_dict:
        summary_path = os.path.join(TOTAL_FILE_PATH, f"{key}_summary.csv")
        df = pd.read_csv(summary_path)
        data_dict = dict_neighbor_dict[key]
        neighbor_1 = None
        neighbor_2 = None
        if len(neighbor_dict[key]) == 1:
            neighbor_1 = neighbor_dict[key][0]
        else:
            neighbor_1 = neighbor_dict[key][0]
            neighbor_2 = neighbor_dict[key][1]
        for _, row in df.iterrows():
            above_edges = row['Number of Edges Connected to ' + neighbor_1]
            if neighbor_2 is not None:
                below_edges = row['Number of Edges Connected to ' + neighbor_2]
            else:
                below_edges = 0
            if above_edges ==0 and below_edges == 0:
                data_dict['floating'] += 1
            elif above_edges != 0 and below_edges ==0:
                data_dict['above_only'] += 1
            elif above_edges == 0 and below_edges != 0:
                data_dict['below_only'] += 1
            else:
                data_dict['both'] +=1
    for i in range(len(neighbor_dict)):
        level = list(neighbor_dict.keys())[i]
        dictionary = list(dict_neighbor_dict.values())[i]
        print(f"{level} dict ", dictionary)


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Count connections between data types")
    parser.add_argument('--data_summary_folder_path', type=str, required=True,
                        help='Path to folder containing subfolders of data summaries for all data types')
    parser.add_argument('--all_versions', action="store_true",
                        help='True if you want to use all versions of Affected Platform Configurations')
    parser.add_argument('--all_years', action="store_true",
                        help='True if you want to use CVE data from all years')
    args = vars(parser.parse_args())
    return args


def main(**args: Dict[str, Any]) -> None:
    data_summary_folder_path, all_versions, all_years = args.values()
    count_contents(data_summary_folder_path, all_versions, all_years)


if __name__ == "__main__":
    kwargs = parse_args(sys.argv[1:])
    main(**kwargs)
