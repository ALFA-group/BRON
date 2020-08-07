import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
import csv
import argparse
import os
import sys
from typing import List, Dict, Any
from ast import literal_eval

"""
Plot number of each data type for specific vendors
"""

def vendor_num_unique_data_types(vendor_search_result):
    _data_source_keys = ("tactic", "technique", "capec", "cwe", "cve", "cpe")
    df = pd.read_csv(vendor_search_result, usecols=_data_source_keys)
    vendor_cpes = set()
    vendor_cves = set()
    vendor_cwes = set()
    vendor_capecs = set()
    vendor_techniques = set()
    vendor_tactics = set()
    _data_source_sets = (vendor_tactics, vendor_techniques, vendor_capecs, vendor_cwes, vendor_cves, vendor_cpes)
    for row_index in df.index[:-1]: # don't use data in last row because it contains sum of each data type
        for key, values in zip(_data_source_keys, _data_source_sets):
            entry = df[key][row_index]
            if entry != "set()": # don't need to call update on empty set and prevents error with literal_eval
                values.update(literal_eval(entry))
    num_unique_data_types = (len(values) for values in _data_source_sets)
    return num_unique_data_types


def threat_info_bar_graph(vendors, search_result_folder, save_path=None):
    plt.rc('font', size=14)
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"
    vendor_threat_info = dict()
    for vendor in vendors:
        vendor_search_result_path = os.path.join(search_result_folder, f"search_result_{vendor}.csv")
        num_cpes, num_cves, num_cwes, num_capecs, num_techniques, num_tactics = vendor_num_unique_data_types(vendor_search_result_path)
        vendor_threat_info[vendor] = {'Tactic': num_tactics, 'Technique': num_techniques, 'Attack Pattern': num_capecs,
                                      'Weakness': num_cwes, 'Vulnerability': num_cves, 'Affected Prod Conf': num_cpes}
    df = pd.DataFrame(vendor_threat_info)
    set_color = ['tab:blue', 'tab:orange', 'lime', 'red', 'tab:purple', 'tab:cyan']
    ax = sns.barplot(x='vendors', y='value', hue='index', edgecolor='black', palette=set_color,
                     data=df.reset_index().melt(id_vars='index', var_name='vendors'))
    ax.set(xlabel="Vendors", ylabel="Occurrence (log)")
    plt.yscale('log')
    plt.xticks(rotation=45)
    plt.ylim(top=400000)
    ax.tick_params(which='both', width=2)
    ax.tick_params(which='major', length=7)
    ax.tick_params(which='minor', length=4)
    handles, labels = ax.get_legend_handles_labels()
    ax.legend(handles=handles[1:], labels=labels[1:])
    plt.legend(loc='upper left', ncol=2, fontsize=12)
    plt.tight_layout()
    if save_path is None:
        plt.show()
    else:
        plt.savefig(save_path, dpi=400)


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Plot number of each data type for specific vendors")
    parser.add_argument('--vendors', type=str, required=True,
                        help='Comma-delimited string containing vendor names, e.g. ibm,mozilla')
    parser.add_argument('--search_result_folder_path', type=str, required=True,
                        help='Path of folder with search results for selected vendors')
    parser.add_argument('--save_path', type=str, required=True, help='Path to save figure')
    args = vars(parser.parse_args())
    return args


def main(**args: Dict[str, Any]) -> None:
    vendors, search_result_folder_path, save_path = args.values()
    vendors_split = vendors.split(',')
    threat_info_bar_graph(vendors_split, search_result_folder_path, save_path=save_path)


if __name__ == "__main__":
    kwargs = parse_args(sys.argv[1:])
    main(**kwargs)
