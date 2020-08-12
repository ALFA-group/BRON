import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
import csv
import gzip
import argparse
import os
import sys
from typing import List, Dict, Any
from ast import literal_eval

"""
Plot number of data types for specific vendor product over all product versions
"""

CPE_ID_BRON_ID_PATH = "BRON/original_id_to_bron_id/cpe_id_bron_id.json"

def sort_versions(versions):
    i = 0
    n = len(versions)
    while i < n:
        if (versions[i] == "*") or (versions[i] == "-"):
            versions.remove(versions[i])
            n -= 1
            continue
        i += 1
    versions.sort(key=lambda s: [int(u) for u in s.split('.')])
    return versions


def vendor_product_versions(BRON_path, vendor, product):
    """
    Return list of versions for vendor product in order from oldest to most recent
    """
    if BRON_path.lower().endswith('.json'):
        with open(BRON_path) as f:
            graph = json.load(f)
    elif BRON_path.lower().endswith('.gz'):
        with gzip.open(BRON_path, "rt", encoding="utf-8") as f:
            graph = json.load(f)
    app_platform_to_versions = dict()
    graph_nodes = graph['nodes']
    for graph_list in graph_nodes:
        attributes = graph_list[1]
        if (attributes["datatype"] == "cpe") and (attributes["metadata"]["vendor"] == vendor):
            app_platform = attributes["metadata"]["product"]
            version = attributes["metadata"]["version"]
            if app_platform not in app_platform_to_versions:
                app_platform_to_versions[app_platform] = []
            app_platform_to_versions[app_platform].append(version)
    versions = sort_versions(app_platform_to_versions[product])
    return versions


def version_to_cpe_ids(BRON_folder_path, vendor, product, starting_point_file, cpe_id_bron_id): # sorted versions
    """
    Return list of 'cpe_' IDs, save starting points
    """
    BRON_path = os.path.join(BRON_folder_path, "BRON.json")
    versions = vendor_product_versions(BRON_path, vendor, product)
    BRON_cpe_id_path = os.path.join(BRON_folder_path, cpe_id_bron_id)
    with open(BRON_cpe_id_path) as f:
        cpe_id_bron_id = json.load(f)
    cpe_ids = []
    id_to_version = dict()
    for version in versions:
        found = False
        for cpe_id in cpe_id_bron_id:
            if f"{vendor}:{product}:{version}" in cpe_id:
                cpe_ids.append(cpe_id)
                id_to_version[f"cpe_{cpe_id_bron_id[cpe_id]}"] = version
                found = True
            if found:
                break
    out = csv.writer(open(starting_point_file,"w"), delimiter=',', quoting=csv.QUOTE_ALL)
    out.writerow(cpe_ids)
    return cpe_ids, id_to_version


def data_types_over_versions(BRON_folder_path, vendor, product, starting_point_file, search_result_file, save_path=None):
    BRON_path = os.path.join(BRON_folder_path, "BRON.json")
    plt.rc('font', size=14)
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"
    # Save file of starting points for vendor product
    _, id_to_version = version_to_cpe_ids(BRON_folder_path, vendor, product, starting_point_file, CPE_ID_BRON_ID_PATH)
    # Run path search on starting points, save file of search results for vendor product
    cmd = f"python -m path_search.path_search_BRON --BRON_path {BRON_path} --starting_point {starting_point_file} --starting_point_type 'cpe' --results_file {search_result_file}"
    sys = os.system(cmd)
    version_to_num_types = {'Version': [], 'Tactic': [], 'Technique': [], 'Attack Pattern': [], 'Weakness': [], 'Vulnerability': []}
    _data_source_keys = ("tactic", "technique", "capec", "cwe", "cve", "cpe")
    _data_source_lists = (version_to_num_types['Tactic'], version_to_num_types['Technique'], version_to_num_types['Attack Pattern'],
                          version_to_num_types['Weakness'], version_to_num_types['Vulnerability'], version_to_num_types['Version'])
    df = pd.read_csv(search_result_file, usecols=_data_source_keys)
    for row_index in df.index[:-1]:
        for key, values in zip(_data_source_keys, _data_source_lists):
            entry = df[key][row_index]
            if key == "cpe": #change
                version = id_to_version[literal_eval(entry).pop()]
                version_to_num_types['Version'].append(version)
            else:
                n_elements = 0
                if entry != "set()":
                    n_elements = len(literal_eval(entry))
                values.append(n_elements)
    df = pd.DataFrame(version_to_num_types)
    ax = sns.lineplot(x='Version', y='value', sort=False, hue='variable', style='variable', markers=True, data=pd.melt(df, ['Version']))
    ax.set(ylabel="Occurrence")
    handles, labels = ax.get_legend_handles_labels()
    ax.legend(handles=handles[1:], labels=labels[1:], loc='upper left', ncol=2, fontsize=12)
    ax.tick_params(which='both', width=2)
    ax.tick_params(which='major', length=7)
    ax.tick_params(which='minor', length=4)
    plt.ylim(top=2) # change this value to adjust y-axis limit
    plt.tight_layout()
    fig = ax.get_figure()
    if save_path is None:
        plt.show()
    else:
        fig.savefig(save_path, dpi=400)


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Plot number of data types for specific vendor product over all product versions")
    parser.add_argument('--BRON_folder_path', type=str, required=True,
                        help='Folder path to BRON graph and files')
    parser.add_argument('--vendor', type=str, required=True,
                        help='Selected vendor')
    parser.add_argument('--product', type=str, required=True,
                        help='Selected product of vendor')
    parser.add_argument('--starting_point_file', type=str, required=True,
                        help='Path to CSV file to save starting points')
    parser.add_argument('--search_result_file', type=str, required=True,
                        help='Path to CSV file to save search results')
    parser.add_argument('--save_path', type=str, required=True, help='Path to save figure')
    args = vars(parser.parse_args())
    return args


def main(**args: Dict[str, Any]) -> None:
    BRON_folder_path, vendor, product, starting_point_file, search_result_file, save_path = args.values()
    data_types_over_versions(BRON_folder_path, vendor, product, starting_point_file, search_result_file, save_path=save_path)


if __name__ == "__main__":
    kwargs = parse_args(sys.argv[1:])
    main(**kwargs)
