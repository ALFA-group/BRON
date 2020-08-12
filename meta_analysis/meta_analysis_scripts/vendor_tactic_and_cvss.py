import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
import seaborn as sns
import json
import argparse
import os
import sys
from typing import List, Dict, Any
from ast import literal_eval

"""
Plot heatmap or violinplot of tactics and vendors
"""

CPE_ID_BRON_ID_PATH = "BRON/original_id_to_bron_id/cpe_id_bron_id.json"

def make_intensity_array(tactics, vendors, tactic_ids, tactic_vendor_products):
    intensity_array = np.zeros((len(vendors),len(tactics)))
    for tactic in tactic_vendor_products:
        for vendor in tactic_vendor_products[tactic]:
            products = tactic_vendor_products[tactic][vendor]
            num_products = len(products)
            intensity_array[vendors.index(vendor)][tactic_ids.index(tactic)] = num_products
    return intensity_array


def bron_id_to_cpe_id(BRON_folder_path):
    BRON_cpe_id_path = os.path.join(BRON_folder_path, CPE_ID_BRON_ID_PATH)
    with open(BRON_cpe_id_path) as f:
        cpe_id_bron_id = json.load(f)
    bron_id_to_cpe_id = dict()
    for cpe_id, bron_id in cpe_id_bron_id.items():
        bron_id_to_cpe_id[f"cpe_{bron_id}"] = cpe_id
    return bron_id_to_cpe_id


def analyze_tactic_result(vendors, tactic_result, bron_id_to_cpe_id):
    df = pd.read_csv(tactic_result, usecols=["tactic", "cpe"])
    tactic_vendor_products = dict()
    for row_index in df.index[:-1]:
        tactic = literal_eval(df["tactic"][row_index]).pop()
        cpes = set()
        entry = df["cpe"][row_index]
        if entry != "set()":
            cpes = literal_eval(entry)
        cpe_ids = find_cpe_ids(cpes, bron_id_to_cpe_id)
        vendor_products = find_vendor_cpes(vendors, cpe_ids)
        tactic_vendor_products[tactic] = vendor_products
    return tactic_vendor_products


def find_vendor_cpes(vendors, cpe_ids):
    vendor_products = dict()
    for vendor in vendors:
        vendor_products[vendor] = set()
    for cpe_id in cpe_ids:
        parsed = cpe_id.split(':', 5)
        vendor = parsed[3]
        product = parsed[4]
        if vendor in vendors:
            vendor_products[vendor].add(product)
    return vendor_products


def find_cpe_ids(cpes, bron_id_to_cpe_id):
    cpe_ids = set()
    for bron_id in cpes:
        cpe_ids.add(bron_id_to_cpe_id[bron_id])
    return cpe_ids


def make_heat_map(tactics, vendors, tactic_ids, tactic_search_result, bron_id_to_cpe_id, save_path=None):
    plt.rc('font', size=12)
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"
    tactic_vendor_products = analyze_tactic_result(vendors, tactic_search_result, bron_id_to_cpe_id)
    intensity_array = make_intensity_array(tactics, vendors, tactic_ids, tactic_vendor_products)
    labels = np.asarray([[int(intensity_array[row, col]) for col in range(len(tactics))] for row in range(len(vendors))])
    comma_fmt = FuncFormatter(lambda x, p: format(int(x), ','))
    heatmap = sns.heatmap(intensity_array, cmap='magma_r', xticklabels=tactics, yticklabels=vendors, annot=labels, fmt='', annot_kws={'size':10}, cbar_kws={'format':comma_fmt})
    # heatmap.set_xticklabels(heatmap.get_xticklabels(), rotation=45, horizontalalignment='right')
    for t in heatmap.texts:
        t.set_text('{:,d}'.format(int(t.get_text())))
    heatmap.set(xlabel="Tactics", ylabel="Vendors")
    heatmap.tick_params(which='both', width=2)
    heatmap.tick_params(which='major', length=7)
    heatmap.tick_params(which='minor', length=4)
    b, t = plt.ylim()
    b += 0.5
    t -= 0.5
    plt.ylim(b, t)
    plt.tight_layout()
    fig = heatmap.get_figure()
    if save_path is None:
        plt.show()
    else:
        fig.savefig(save_path, dpi=400)


def cve_to_risk(cve_summary):
    cve_to_risk_dict = dict()
    df = pd.read_csv(cve_summary, usecols=["node_name", "metadata"])
    for row_index in df.index:
        cve = df["node_name"][row_index]
        metadata = literal_eval(df["metadata"][row_index])
        risk_score = metadata["weight"]
        cve_to_risk_dict[cve] = risk_score
    return cve_to_risk_dict


# Violin plots for vendor applications that reach a specific tactic
def max_cve_risk_violin_tactic_helper(tactic, vendors, vendor_search_result_folder, cve_to_risk_dict,
                                      tactic_search_result, bron_id_to_cpe_id):
    tactic_vendor_products = analyze_tactic_result(vendors, tactic_search_result, bron_id_to_cpe_id)
    vendor_products = tactic_vendor_products[tactic] # dict of vendors to set of their products
    vendor_to_risk_score = dict()
    for vendor in vendors:
        VENDOR_SEARCH_RESULT_PATH = os.path.join(vendor_search_result_folder, "search_result_" + vendor + ".csv")
        df = pd.read_csv(VENDOR_SEARCH_RESULT_PATH, usecols=["tactic", "cve"])
        risk_score_list = []
        for row_index in df.index[:-1]:
            tactics = set()
            tactics_entry = df["tactic"][row_index]
            if tactics_entry != "set()":
                tactics = literal_eval(tactics_entry)
            cves = set()
            cves_entry = df["cve"][row_index]
            if cves_entry != "set()":
                cves = literal_eval(cves_entry)
            if tactic in tactics:
                max_cve_risk = None
                for cve in cves:
                    cve_risk = cve_to_risk_dict[cve]
                    if max_cve_risk is None:
                        max_cve_risk = cve_risk
                    elif max_cve_risk < cve_risk:
                        max_cve_risk = cve_risk
                risk_score_list.append(max_cve_risk)
        vendor_to_risk_score[vendor] = risk_score_list
    return vendor_to_risk_score


def max_cve_risk_violin_tactic(tactic_names, tactic_ids, vendors, vendor_search_result_folder,
                               cve_to_risk_dict, tactic_search_result, bron_id_to_cpe_id, save_path=None, stick=False):
    tactic1_name, tactic2_name = tactic_names
    tactic1_id, tactic2_id = tactic_ids
    plt.rcParams['figure.figsize'] = (20.0, 12.0)
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"
    sns.set(font_scale=3)
    sns.set_style("ticks")
    vendor_to_risk_score_dict1 = max_cve_risk_violin_tactic_helper(tactic1_id, vendors, vendor_search_result_folder,
                                                                   cve_to_risk_dict, tactic_search_result, bron_id_to_cpe_id)
    vendor_to_risk_score_dict2 = max_cve_risk_violin_tactic_helper(tactic2_id, vendors, vendor_search_result_folder,
                                                                   cve_to_risk_dict, tactic_search_result, bron_id_to_cpe_id)
    combined_data = {'Tactic': [], 'Vendor': [], 'CVSS Scores': []}
    for vendor, risk_score_list in vendor_to_risk_score_dict1.items():
        for risk_score in risk_score_list:
            combined_data['Tactic'].append(tactic1_name)
            combined_data['Vendor'].append(vendor)
            combined_data['CVSS Scores'].append(risk_score)
    for vendor, risk_score_list in vendor_to_risk_score_dict2.items():
        for risk_score in risk_score_list:
            combined_data['Tactic'].append(tactic2_name)
            combined_data['Vendor'].append(vendor)
            combined_data['CVSS Scores'].append(risk_score)
    vendor_to_risk_score_df = pd.DataFrame(combined_data)
    if stick:
        p = sns.violinplot(data=vendor_to_risk_score_df, x='Vendor', y='CVSS Scores', hue='Tactic', split=True, inner="stick")
    else:
        p = sns.violinplot(data=vendor_to_risk_score_df, x='Vendor', y='CVSS Scores', hue='Tactic', split=True)
    p.tick_params(which='both', width=4)
    p.tick_params(which='major', length=14)
    plt.legend(fontsize=30)
    p.set(xlabel="Vendors", ylabel="CVSS Scores")
    plt.xticks(rotation=45)
    plt.ylim(-1.5, 11.5)
    plt.tight_layout()
    if save_path is None:
        plt.show()
    else:
        plt.savefig(save_path, dpi=400)


# Violin plots for vendor applications that reach all of their tactics
def max_cve_risk_violin_helper(vendors, vendor_search_result_folder, cve_to_risk_dict):
    vendor_to_risk_score = dict()
    for vendor in vendors:
        VENDOR_SEARCH_RESULT_PATH = os.path.join(vendor_search_result_folder, "search_result_" + vendor + ".csv")
        df = pd.read_csv(VENDOR_SEARCH_RESULT_PATH, usecols=["cve"])
        risk_score_list = []
        for row_index in df.index[:-1]:
            cves = set()
            entry = df["cve"][row_index]
            if entry != "set()":
                cves = literal_eval(entry)
            max_cve_risk = None
            for cve in cves:
                cve_risk = cve_to_risk_dict[cve]
                if max_cve_risk is None:
                    max_cve_risk = cve_risk
                elif max_cve_risk < cve_risk:
                    max_cve_risk = cve_risk
            risk_score_list.append(max_cve_risk)
        vendor_to_risk_score[vendor] = risk_score_list
    vendor_to_risk_score_df = pd.DataFrame(dict([ (k,pd.Series(v)) for k,v in vendor_to_risk_score.items() ]))
    return vendor_to_risk_score_df


def max_cve_risk_violin(vendors, vendor_search_result_folder, cve_to_risk_dict, save_path=None, stick=False):
    """
    Returns violin plot with vendors on x-axis and max cve risk scores on y-axis
    """
    plt.rcParams['figure.figsize'] = (20.0, 12.0)
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"
    sns.set(font_scale=3)
    sns.set_style("ticks")
    vendor_to_risk_score_df = max_cve_risk_violin_helper(vendors, vendor_search_result_folder, cve_to_risk_dict)
    if stick:
        p = sns.violinplot(data=vendor_to_risk_score_df, inner="stick")
    else:
        p = sns.violinplot(data=vendor_to_risk_score_df)
    p.tick_params(which='both', width=4)
    p.tick_params(which='major', length=14)
    p.set(xlabel="Vendors", ylabel="CVSS Scores")
    plt.xticks(rotation=45)
    plt.ylim(-1.5, 11.5)
    plt.tight_layout()
    if save_path is None:
        plt.show()
    else:
        plt.savefig(save_path, dpi=400)


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Plot heatmap or violinplot of tactics and vendors")
    parser.add_argument('--tactics', type=str, required=True,
                        help='Comma-delimited string containing tactic names, e.g. discovery,defense-evasion')
    parser.add_argument('--vendors', type=str, required=True,
                        help='Comma-delimited string containing vendor names, e.g. ibm,mozilla')
    parser.add_argument('--tactic_search_result_file', type=str, required=True,
                        help='Path to file with search result for selected tactics')
    parser.add_argument('--vendor_search_result_folder', type=str, required=True,
                        help='Path to folder with search results for selected vendors')
    parser.add_argument('--plot_type', type=str, required=True,
                        help='Either heatmap, violinplot, or two-tactic-violinplot')
    parser.add_argument('--violin_stick', action="store_true",
                        help='True if you want to add sticks to violinplot')
    parser.add_argument('--cve_summary_path', type=str, required=True,
                        help='Path to file containing CVE data summary')
    parser.add_argument('--BRON_folder_path', type=str, required=True,
                        help='Folder path to BRON graph and files')
    parser.add_argument('--save_path', type=str, required=True, help='Path to save figure')
    args = vars(parser.parse_args())
    return args


def main(**args: Dict[str, Any]) -> None:
    tactics, vendors, tactic_search_result_file, vendor_search_result_folder, plot_type, violin_stick, cve_summary_path, BRON_folder_path, save_path = args.values()
    tactics_split = tactics.split(',')
    vendors_split = vendors.split(',')
    bron_id_to_cpe_id_dict = bron_id_to_cpe_id(BRON_folder_path)
    cve_to_risk_dict = cve_to_risk(cve_summary_path)
    all_tactics_name_to_id = {"persistence": "tactic_00008", "privilege-escalation": "tactic_00021",
                              "discovery": "tactic_00014", "initial-access": "tactic_00089",
                              "lateral-movement": "tactic_00026", "execution": "tactic_00038",
                              "credential-access": "tactic_00006", "defense-evasion": "tactic_00012",
                              "impact": "tactic_00240", "command-and-control": "tactic_00002",
                              "exfiltration": "tactic_00004", "collection": "tactic_00010"}
    if plot_type == 'heatmap':
        tactic_ids = []
        for tactic in tactics_split:
            tactic_ids.append(all_tactics_name_to_id[tactic])
        make_heat_map(tactics_split, vendors_split, tactic_ids, tactic_search_result_file, bron_id_to_cpe_id_dict, save_path=save_path)
    elif plot_type == 'violinplot':
        max_cve_risk_violin(vendors_split, vendor_search_result_folder, cve_to_risk_dict, save_path=save_path, stick=violin_stick)
    elif plot_type == 'two-tactic-violinplot':
        if len(tactics_split) == 2:
            tactic_ids = [all_tactics_name_to_id[tactics_split[0]], all_tactics_name_to_id[tactics_split[1]]]
            max_cve_risk_violin_tactic(tactics_split, tactic_ids, vendors_split, vendor_search_result_folder, cve_to_risk_dict,
                                       tactic_search_result_file, bron_id_to_cpe_id_dict, save_path=save_path, stick=violin_stick)
        else:
            print("Error: There must be exactly 2 Tactics")


if __name__ == "__main__":
    kwargs = parse_args(sys.argv[1:])
    main(**kwargs)
