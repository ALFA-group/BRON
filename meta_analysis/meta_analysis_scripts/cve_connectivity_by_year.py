import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import matplotlib as mpl
from matplotlib.ticker import (MultipleLocator, FormatStrFormatter, AutoMinorLocator)
import seaborn as sns
import json
import csv
import argparse
import os
import sys
from typing import List, Dict, Any

"""
Plot number and percentage of Vulnerabilities connected to a Tactic, Attack Pattern, or Weakness
"""

CVE_ID_BRON_ID_PATH = "BRON/original_id_to_bron_id/cve_id_bron_id.json"

def cves_by_year(years, BRON_folder_path):
    BRON_cve_id_path = os.path.join(BRON_folder_path, CVE_ID_BRON_ID_PATH)
    with open(BRON_cve_id_path) as f:
        cve_id_bron_id = json.load(f)
    year_to_cve_ids = dict()
    for year in years:
        year_to_cve_ids[year] = []
    for cve_id in cve_id_bron_id:
        cve_year = cve_id.split("-")[1]
        if cve_year in years:
            year_to_cve_ids[cve_year].append(cve_id)
    year_to_num_cve_ids = dict()
    for cve_year in year_to_cve_ids:
        year_to_num_cve_ids[cve_year] = len(year_to_cve_ids[cve_year])
    return year_to_num_cve_ids


def make_stacked_bar(data_dict_1, data_dict_2, data_dict_3, data_dict_4, data_dict_5,
                     data_name_1, data_name_2, data_name_3, data_name_4, data_name_5, save_path=None):
    plt.rc('font', size=14)
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"
    x_vals = []
    y_vals_1 = []
    y_vals_2 = []
    y_vals_3 = []
    y_vals_4 = []
    y_vals_5 = []
    for key in data_dict_1:
        x_vals.append(key)
        y_vals_1.append(data_dict_1[key])
        y_vals_2.append(data_dict_2[key])
        y_vals_3.append(data_dict_3[key])
        y_vals_4.append(data_dict_4[key])
        y_vals_5.append(data_dict_5[key])
    y_vals_2_sum = []
    y_vals_3_sum = []
    y_vals_4_sum = []
    y_vals_5_sum = []
    for i in range(len(y_vals_1)):
        y_vals_2_sum.append(y_vals_1[i] + y_vals_2[i])
        y_vals_3_sum.append(y_vals_1[i] + y_vals_2[i] + y_vals_3[i])
        y_vals_4_sum.append(y_vals_1[i] + y_vals_2[i] + y_vals_3[i] + y_vals_4[i])
    fig, ax = plt.subplots()
    bar_1 = plt.bar(x_vals, y_vals_1, color='black', edgecolor='black')
    bar_2 = plt.bar(x_vals, y_vals_2, bottom=y_vals_1, edgecolor='black')
    bar_3 = plt.bar(x_vals, y_vals_3, bottom=y_vals_2_sum, color='gray', edgecolor='black')
    bar_4 = plt.bar(x_vals, y_vals_4, bottom=y_vals_3_sum, color='lightgray', edgecolor='black')
    bar_5 = plt.bar(x_vals, y_vals_5, bottom=y_vals_4_sum, color='white', edgecolor='black')
    plt.legend([bar_1, bar_3, bar_4, bar_5],
               [data_name_1, data_name_3, data_name_4, data_name_5], fontsize=11, loc='upper left')
    plt.xlabel("Year")
    plt.ylabel("Fraction")
    plt.xticks(rotation=45)
    ax.set_xticks(ax.get_xticks()[::2])
    ax.xaxis.set_minor_locator(AutoMinorLocator(2))
    ax.tick_params(which='both', width=2)
    ax.tick_params(which='major', length=7)
    ax.tick_params(which='minor', length=4)
    plt.tight_layout()
    if save_path is None:
        plt.show()
    else:
        plt.savefig(save_path, dpi=400)


def make_line_plot(data_dict_1, data_dict_2, data_dict_3, data_dict_4, data_dict_5,
                   data_name_1, data_name_2, data_name_3, data_name_4, data_name_5, years, save_path=None):
    plt.rc('font', size=14)
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"
    y_vals_1 = []
    y_vals_2 = []
    y_vals_3 = []
    y_vals_4 = []
    y_vals_5 = []
    for year in years:
        y_vals_1.append(data_dict_1[year])
        y_vals_2.append(data_dict_2[year]-data_dict_1[year])
        y_vals_3.append(data_dict_3[year]-data_dict_2[year])
        y_vals_4.append(data_dict_4[year]-data_dict_3[year])
        y_vals_5.append(data_dict_5[year]-data_dict_4[year])
    fig, ax = plt.subplots()
    ax.plot(years, y_vals_5, '--', color='tab:purple', marker='D')
    ax.plot(years, y_vals_4, '-.', color='tab:red', marker='P')
    ax.plot(years, y_vals_3, ':', color='tab:green', marker='s')
    ax.plot(years, y_vals_1, color='tab:blue', marker='o')
    purple_line = mlines.Line2D([], [], color='tab:purple', linestyle='--', marker='D', label=data_name_5)
    red_line = mlines.Line2D([], [], color='tab:red', linestyle='-.', marker='P', label=data_name_4)
    green_line = mlines.Line2D([], [], color='tab:green', linestyle=':', marker='s', label=data_name_3)
    blue_line = mlines.Line2D([], [], color='tab:blue', marker='o', label=data_name_1)
    plt.legend(handles=[blue_line, green_line, red_line, purple_line], fontsize=11, loc='upper left')
    plt.xlabel("Year")
    plt.ylabel("Occurrence")
    plt.xticks(rotation=45)
    # ax.set_xticks(ax.get_xticks()[::2])
    # ax.xaxis.set_minor_locator(AutoMinorLocator(2))
    ax.yaxis.set_major_formatter(mpl.ticker.StrMethodFormatter('{x:,.0f}'))
    ax.tick_params(which='both', width=2)
    ax.tick_params(which='major', length=7)
    ax.tick_params(which='minor', length=4)
    plt.ylim(top=15) # change this value to adjust y-axis limit
    plt.tight_layout()
    if save_path is None:
        plt.show()
    else:
        plt.savefig(save_path, dpi=400)


def cve_connectivity_by_year(years, search_result_folder, number_or_percent, BRON_folder_path, save_path=None):
    year_to_num_cve_ids = cves_by_year(years, BRON_folder_path)
    tactic_connected = dict()
    technique_connected = dict()
    capec_connected = dict()
    cwe_connected = dict()
    for year in years:
        tactic_connected[year] = 0
        technique_connected[year] = 0
        capec_connected[year] = 0
        cwe_connected[year] = 0
    _data_source_keys = ("tactic", "technique", "capec", "cwe")
    _data_source_dicts = (tactic_connected, technique_connected, capec_connected, cwe_connected)
    for year in years:
        search_result_path = os.path.join(search_result_folder, f"search_result_cve_{year}.csv")
        df = pd.read_csv(search_result_path, usecols=_data_source_keys)
        for row_index in df.index[:-1]: # don't use data in last row because it contains sum of each data type
            for key, values in zip(_data_source_keys, _data_source_dicts):
                entry = df[key][row_index]
                if entry != "set()": # check if entry contains at least one element in set
                    values[year] += 1
    if number_or_percent == 'number':
        make_line_plot(tactic_connected, technique_connected, capec_connected, cwe_connected, year_to_num_cve_ids,
                       'Tactic to Vulnerability Path', 'Path From Technique to Vulnerability', 'Attack Pattern to Vulnerability Path',
                       'Weakness to Vulnerability Path', 'Unlinked Vulnerability', years, save_path=save_path)
    elif number_or_percent == 'percent':
        tactic_percent = dict()
        technique_percent = dict()
        capec_percent = dict()
        cwe_percent = dict()
        total_percent = dict()
        for year in years:
            year_num_cves = year_to_num_cve_ids[year]
            tactic_percent[year] = tactic_connected[year]/year_num_cves
            technique_percent[year] = (technique_connected[year]-tactic_connected[year])/year_num_cves
            capec_percent[year] = (capec_connected[year]-technique_connected[year])/year_num_cves
            cwe_percent[year] = (cwe_connected[year]-capec_connected[year])/year_num_cves
            total_percent[year] = (year_to_num_cve_ids[year]-cwe_connected[year])/year_num_cves
        make_stacked_bar(tactic_percent, technique_percent, capec_percent, cwe_percent, total_percent,
                         'Tactic to Vulnerability Path', 'Technique to Vulnerability Path', 'Attack Pattern to Vulnerability Path',
                         'Weakness to Vulnerability Path', 'Unlinked Vulnerability', save_path=save_path)


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Plot number and percentage of Vulnerabilities connected to a Tactic, Attack Pattern, or Weakness")
    parser.add_argument('--years', type=str, required=True,
                        help='Comma-delimited string containing years, e.g. 2018,2019,2020')
    parser.add_argument('--search_result_folder_path', type=str, required=True,
                        help='Path to folder with search results for selected CVE years')
    parser.add_argument('--number_or_percent', type=str, required=True, help='Either number or percent to determine plot type')
    parser.add_argument('--BRON_folder_path', type=str, required=True, help='Folder path to BRON graph and files')
    parser.add_argument('--save_path', type=str, required=True, help='Path to save figure')
    args = vars(parser.parse_args())
    return args


def main(**args: Dict[str, Any]) -> None:
    years, search_result_folder_path, number_or_percent, BRON_folder_path, save_path = args.values()
    years_split = years.split(',')
    cve_connectivity_by_year(years_split, search_result_folder_path, number_or_percent, BRON_folder_path, save_path=save_path)


if __name__ == "__main__":
    kwargs = parse_args(sys.argv[1:])
    main(**kwargs)
