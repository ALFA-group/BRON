import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import matplotlib as mpl
from matplotlib.ticker import (MultipleLocator, FormatStrFormatter, AutoMinorLocator)
from matplotlib.patches import Patch
import numpy as np
import seaborn as sns
import statistics
import argparse
import os
import sys
from typing import List, Dict, Any

"""
Plot number of edges for specific data type
"""

def read_threat_data_csv(threat_data_type, all_cves, all_versions, data_summary_folder_path, include_floating=False):
    '''
    :param threat_data_type: data type to make edge distribution of
    :param all_cves: True means all cves will be included; False means only 2015-2020 will be included
    :param all_versions: True means all CPE/App-Platform versions used; False means only latest version used
    :param data_summary_folder_path: path to folder that stores data summary results
    :param include_floating: True to include floating nodes in edge distribution
    :return: list of edge counts
    '''
    neighbor_dict = {'tactic': ['technique'], 'technique': ['tactic', 'capec'], 'capec': ['technique', 'cwe'],
                     'cwe': ['capec', 'cve'],
                     'cve': ['cwe', 'cpe'], 'cpe': ['cve']}
    title_dict = {'all_cves_all_versions': 'All CVEs and All Versions',
                  'all_cves_latest_version': 'All CVEs and Latest Version',
                  'recent_cves_all_versions': 'Recent CVEs and All Versions',
                  'recent_cves_latest_version': 'Recent CVEs and Latest Version'}
    capitalized = {'tactic': 'Tactic', 'technique': 'Technique', 'capec': 'CAPEC', 'cwe': 'CWE', 'cve': 'CVE',
                   'cpe': 'CPE'}
    if all_cves:
        cve_abbrev = 'all_cves_'
    else:
        cve_abbrev = 'recent_cves_'
    if all_versions:
        version_abbrev = 'all_versions'
    else:
        version_abbrev = 'latest_version'
    summary_path = os.path.join(data_summary_folder_path, f"{cve_abbrev}{version_abbrev}", f"{threat_data_type}_summary.csv")
    df = pd.read_csv(summary_path)
    edges = []
    neighbor_1 = None
    neighbor_2 = None
    if len(neighbor_dict[threat_data_type]) == 1:
        neighbor_1 = neighbor_dict[threat_data_type][0]
    else:
        neighbor_1 = neighbor_dict[threat_data_type][0]
        neighbor_2 = neighbor_dict[threat_data_type][1]
    for _, row in df.iterrows():
        edges_1 = row['Number of Edges Connected to ' + neighbor_1]
        if not include_floating:
            if edges_1 != 0:
                edges.append(edges_1)
        else:
            edges.append(edges_1)
        if neighbor_2 is not None:
            edges_2 = row['Number of Edges Connected to ' + neighbor_2]
            if not include_floating:
                if edges_2 != 0:
                    edges.append(edges_2)
            else:
                edges.append(edges_2)
    return edges


def tactic_edge_hist(data_summary_folder_path, save_path=None):
    plt.rc('font', size=20)
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"
    plt.figure(figsize=(6.25, 5))
    all_versions = read_threat_data_csv('tactic', True, True, data_summary_folder_path)
    all_versions_color = "tab:blue"
    num_bins = 5
    fig, ax = plt.subplots()
    plt.hist(all_versions, bins=num_bins, color=all_versions_color, edgecolor='black')
    ax.xaxis.set_major_locator(MultipleLocator(10))
    ax.xaxis.set_minor_locator(AutoMinorLocator(2))
    ax.tick_params(which='both', width=3)
    ax.tick_params(which='major', length=10.5)
    ax.tick_params(which='minor', length=6)
    plt.xlabel(f'Number of Techniques')
    plt.ylabel(f'Number of Tactics')
    plt.tight_layout()
    if save_path is None:
        plt.show()
    else:
        plt.savefig(save_path, dpi=400)


def cwe_edge_hist(data_summary_folder_path, save_path=None):
    plt.rc('font', size=14)
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"
    all_cves = read_threat_data_csv('cwe', True, True, data_summary_folder_path)
    recent_cves = read_threat_data_csv('cwe', False, True, data_summary_folder_path)
    set_bins = np.linspace(min(all_cves), max(all_cves), num=13)
    bin_width = 360
    all_cves_color = "tomato"
    recent_cves_color = "pink"
    x_vals = 0.5*(set_bins[1:]+set_bins[:-1]) - 0.5*bin_width
    x_vals_2 = 0.5*(set_bins[1:]+set_bins[:-1]) + 0.5*bin_width
    all_cves_counts, _ = np.histogram(all_cves, bins=set_bins)
    recent_cves_counts, _ = np.histogram(recent_cves, bins=set_bins)
    ax_1 = plt.subplot(1,1,1)
    bar_1 = ax_1.bar(x_vals, all_cves_counts, width=bin_width, color=all_cves_color, edgecolor='black', hatch='OO')
    bar_2 = ax_1.bar(x_vals_2, recent_cves_counts, width=bin_width, color=recent_cves_color, edgecolor='black', hatch='..')
    plt.legend([bar_1, bar_2], ['All Vulnerabilities', 'Recent Vulnerabilities'], fontsize=12)
    plt.yscale('log')
    plt.xlim(right=12200)
    ax_1.xaxis.set_major_formatter(mpl.ticker.StrMethodFormatter('{x:,.0f}'))
    ax_1.xaxis.set_minor_locator(AutoMinorLocator(5))
    ax_1.tick_params(which='both', width=2)
    ax_1.tick_params(which='major', length=7)
    ax_1.tick_params(which='minor', length=4)
    plt.locator_params(axis='x', nbins=6)
    plt.xlabel('Number of Edges')
    plt.ylabel('Number of Weaknesses (log)')
    plt.tight_layout()
    if save_path is None:
        plt.show()
    else:
        plt.savefig(save_path, dpi=400)


def cve_cpe_edge_hist(data_type, data_summary_folder_path, save_path=None):
    plt.rc('font', size=14)
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"
    all_cves_all_versions = read_threat_data_csv(data_type, True, True, data_summary_folder_path)
    all_cves_latest_version = read_threat_data_csv(data_type, True, False, data_summary_folder_path)
    recent_cves_all_versions = read_threat_data_csv(data_type, False, True, data_summary_folder_path)
    recent_cves_latest_version = read_threat_data_csv(data_type, False, False, data_summary_folder_path)
    if data_type == 'cve':
        bin_width = 133
        all_cves_all_versions_color = "mediumorchid"
        all_cves_latest_version_color = "violet"
        recent_cves_all_versions_color = "magenta"
        recent_cves_latest_version_color = "hotpink"
    elif data_type == 'cpe':
        bin_width = 67
        all_cves_all_versions_color = "darkturquoise"
        all_cves_latest_version_color = "deepskyblue"
        recent_cves_all_versions_color = "cyan"
        recent_cves_latest_version_color = "lightskyblue"
    set_bins = np.linspace(min(all_cves_all_versions), max(all_cves_all_versions), num=9)
    x_vals = 0.5*(set_bins[1:]+set_bins[:-1]) - 1.5*bin_width
    x_vals_2 = 0.5*(set_bins[1:]+set_bins[:-1]) - 0.5*bin_width
    x_vals_3 = 0.5*(set_bins[1:]+set_bins[:-1]) + 0.5*bin_width
    x_vals_4 = 0.5*(set_bins[1:]+set_bins[:-1]) + 1.5*bin_width
    all_cves_all_versions_counts, _ = np.histogram(all_cves_all_versions, bins=set_bins)
    all_cves_latest_version_counts, _ = np.histogram(all_cves_latest_version, bins=set_bins)
    recent_cves_all_versions_counts, _ = np.histogram(recent_cves_all_versions, bins=set_bins)
    recent_cves_latest_version_counts, _ = np.histogram(recent_cves_latest_version, bins=set_bins)
    ax_1 = plt.subplot(1,1,1)
    bar_1 = ax_1.bar(x_vals, all_cves_all_versions_counts, width=bin_width, color=all_cves_all_versions_color, edgecolor='black', hatch='OO')
    bar_2 = ax_1.bar(x_vals_2, recent_cves_all_versions_counts, width=bin_width, color=recent_cves_all_versions_color, edgecolor='black', hatch='..')
    bar_3 = ax_1.bar(x_vals_3, all_cves_latest_version_counts, width=bin_width, color=all_cves_latest_version_color, edgecolor='black', hatch='OO')
    bar_4 = ax_1.bar(x_vals_4, recent_cves_latest_version_counts, width=bin_width, color=recent_cves_latest_version_color, edgecolor='black', hatch='..')
    plt.legend([bar_1, bar_2, bar_3, bar_4],
               ['All Vulnerabilities,\nAll Affected Prod Conf Versions', 'Recent Vulnerabilities,\nAll Affected Prod Conf Versions',
                'All Vulnerabilities,\nLatest Affected Prod Conf Versions', 'Recent Vulnerabilities,\nLatest Affected Prod Conf Versions'],
                fontsize=12)
    plt.xlabel('Number of Edges')
    ax_1.xaxis.set_major_formatter(mpl.ticker.StrMethodFormatter('{x:,.0f}'))
    ax_1.xaxis.set_minor_locator(AutoMinorLocator(5))
    ax_1.tick_params(which='both', width=2)
    ax_1.tick_params(which='major', length=7)
    ax_1.tick_params(which='minor', length=4)
    plt.yscale('log')
    if data_type == 'cve':
        plt.ylabel('Number of Vulnerabilities (log)')
        plt.xlim(right=4750)
    elif data_type == 'cpe':
        plt.ylabel('Number of Affected Prod Confs (log)')
        plt.xlim(right=2500)
        plt.locator_params(axis='x', nbins=5)
    plt.tight_layout()
    if save_path is None:
        plt.show()
    else:
        plt.savefig(save_path, dpi=400)


def read_threat_data_csv_specific(threat_data_type, all_cves, all_versions, data_summary_folder_path,
                                  technique_tactic=False, technique_capec=False, capec_technique=False, capec_cwe=False, include_floating=False):
    '''
    :param threat_data_type: data type to make edge distribution of
    :param all_cves: True means all cves will be included; False means only 2015-2020 will be included
    :param all_versions: True means all CPE/App-Platform versions used; False means only latest version used
    :param data_summary_folder_path: path to folder that stores data summary results
    :param technique_tactic: True means technique edges that reach a tactic are used
    :param technique_capec: True means technique edges that reach a capec are used
    :param capec_technique: True means capec edges that reach a technique are used
    :param capec_cwe: True means capec edges that reach a cwe are used
    :param include_floating: True to include floating nodes in edge distribution
    :return: list of edge counts
    '''
    neighbor_dict = {'tactic': ['technique'], 'technique': ['tactic', 'capec'], 'capec': ['technique', 'cwe'],
                     'cwe': ['capec', 'cve'],
                     'cve': ['cwe', 'cpe'], 'cpe': ['cve']}
    title_dict = {'all_cves_all_versions': 'All CVEs and All Versions',
                  'all_cves_latest_version': 'All CVEs and Latest Version',
                  'recent_cves_all_versions': 'Recent CVEs and All Versions',
                  'recent_cves_latest_version': 'Recent CVEs and Latest Version'}
    capitalized = {'tactic': 'Tactic', 'technique': 'Technique', 'capec': 'CAPEC', 'cwe': 'CWE', 'cve': 'CVE',
                   'cpe': 'CPE'}
    if all_cves:
        cve_abbrev = 'all_cves_'
    else:
        cve_abbrev = 'recent_cves_'
    if all_versions:
        version_abbrev = 'all_versions'
    else:
        version_abbrev = 'latest_version'
    summary_path = os.path.join(data_summary_folder_path, f"{cve_abbrev}{version_abbrev}", f"{threat_data_type}_summary.csv")
    df = pd.read_csv(summary_path)
    edges = []
    neighbor_1 = None
    neighbor_2 = None
    if len(neighbor_dict[threat_data_type]) == 1:
        neighbor_1 = neighbor_dict[threat_data_type][0]
    else:
        if threat_data_type == 'capec' and capec_technique:
            neighbor_1 = neighbor_dict[threat_data_type][0]
        elif threat_data_type == 'capec' and capec_cwe:
            neighbor_1 = neighbor_dict[threat_data_type][1]
        if threat_data_type == 'technique' and technique_tactic:
            neighbor_1 = neighbor_dict[threat_data_type][0]
        elif threat_data_type == 'technique' and technique_capec:
            neighbor_1 = neighbor_dict[threat_data_type][1]
    for _, row in df.iterrows():
        edges_1 = row['Number of Edges Connected to ' + neighbor_1]
        if not include_floating:
            if edges_1 != 0:
                edges.append(edges_1)
        else:
            edges.append(edges_1)
        if neighbor_2 is not None:
            edges_2 = row['Number of Edges Connected to ' + neighbor_2]
            if not include_floating:
                if edges_2 != 0:
                    edges.append(edges_2)
            else:
                edges.append(edges_2)
    return edges


def technique_edge_hist(data_summary_folder_path, save_path=None):
    plt.rc('font', size=14)
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"
    plt.figure(figsize=(6.25, 5))
    all_capec = read_threat_data_csv_specific('technique', True, True, data_summary_folder_path, technique_tactic=True)
    capec_to_cwe = read_threat_data_csv_specific('technique', True, True, data_summary_folder_path, technique_capec=True)
    capec_to_technique_color = 'tab:orange'
    capec_to_cwe_color = 'navajowhite'
    set_bins = np.linspace(1.0, 5.0, num=5)
    bin_width = 0.45
    x_vals = 0.5*(set_bins[1:]+set_bins[:-1]) - 0.5*bin_width
    x_vals_2 = 0.5*(set_bins[1:]+set_bins[:-1]) + 0.5*bin_width
    all_capec_counts, _ = np.histogram(all_capec, bins=set_bins)
    capec_to_cwe_counts, _ = np.histogram(capec_to_cwe, bins=set_bins)
    ax_1 = plt.subplot(1,1,1)
    bar_1 = ax_1.bar(x_vals, all_capec_counts, width=bin_width, color=capec_to_technique_color, edgecolor='black', hatch='OO')
    bar_2 = ax_1.bar(x_vals_2, capec_to_cwe_counts, width=bin_width, color=capec_to_cwe_color, edgecolor='black', hatch='..')
    plt.legend([bar_1, bar_2], ['Technique-\nTactic Edges', 'Technique-\nAttack Pattern Edges'], fontsize=12)
    ax_1.tick_params(which='both', width=3)
    ax_1.tick_params(which='major', length=10.5)
    ax_1.tick_params(which='minor', length=6)
    plt.xlabel('Number of Edges')
    plt.ylabel('Number of Techniques')
    plt.tight_layout()
    if save_path is None:
        plt.show()
    else:
        plt.savefig(save_path, dpi=400)


def capec_edge_hist(data_summary_folder_path, save_path=None):
    plt.rc('font', size=20)
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"
    plt.figure(figsize=(6.25, 5))
    all_capec = read_threat_data_csv_specific('capec', True, True, data_summary_folder_path, capec_technique=True)
    capec_to_cwe = read_threat_data_csv_specific('capec', True, True, data_summary_folder_path, capec_cwe=True)
    capec_to_technique_color = 'tab:green'
    capec_to_cwe_color = 'lime'
    set_bins = np.linspace(1.0, 13.0, num=13)
    bin_width = 0.4
    x_vals = 0.5*(set_bins[1:]+set_bins[:-1]) - 0.5*bin_width
    x_vals_2 = 0.5*(set_bins[1:]+set_bins[:-1]) + 0.5*bin_width
    all_capec_counts, _ = np.histogram(all_capec, bins=set_bins)
    capec_to_cwe_counts, _ = np.histogram(capec_to_cwe, bins=set_bins)
    ax_1 = plt.subplot(1,1,1)
    bar_1 = ax_1.bar(x_vals, all_capec_counts, width=bin_width, color=capec_to_technique_color, edgecolor='black', hatch='OO')
    bar_2 = ax_1.bar(x_vals_2, capec_to_cwe_counts, width=bin_width, color=capec_to_cwe_color, edgecolor='black', hatch='..')
    plt.legend([bar_1, bar_2], ['Attack Pattern-\nTechnique Edges', 'Attack Pattern-\nWeakness Edges'], fontsize=18)
    ax_1.xaxis.set_major_locator(MultipleLocator(2))
    ax_1.xaxis.set_minor_locator(AutoMinorLocator(2))
    ax_1.tick_params(which='both', width=3)
    ax_1.tick_params(which='major', length=10.5)
    ax_1.tick_params(which='minor', length=6)
    plt.xlabel('Number of Edges')
    plt.ylabel('Number of Attack Patterns')
    plt.tight_layout()
    if save_path is None:
        plt.show()
    else:
        plt.savefig(save_path, dpi=400)


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Plot number of edges for specific data type")
    parser.add_argument('--data_summary_folder_path', type=str, required=True,
                        help='Path to folder containing subfolders of data summaries for all data types')
    parser.add_argument('--data_type', type=str, required=True,
                        help='Either tactic, technique, capec, cwe, cve, or cpe')
    parser.add_argument('--save_path', type=str, required=True, help='Path to save figure')
    args = vars(parser.parse_args())
    return args


def main(**args: Dict[str, Any]) -> None:
    data_summary_folder_path, data_type, save_path = args.values()
    if data_type == "tactic":
        tactic_edge_hist(data_summary_folder_path, save_path=save_path)
    elif data_type == "technique":
        technique_edge_hist(data_summary_folder_path, save_path=save_path)
    elif data_type == "capec":
        capec_edge_hist(data_summary_folder_path, save_path=save_path)
    elif data_type == "cwe":
        cwe_edge_hist(data_summary_folder_path, save_path=save_path)
    elif data_type == "cve":
        cve_cpe_edge_hist('cve', data_summary_folder_path, save_path=save_path)
    elif data_type == "cpe":
        cve_cpe_edge_hist('cpe', data_summary_folder_path, save_path=save_path)


if __name__ == "__main__":
    kwargs = parse_args(sys.argv[1:])
    main(**kwargs)
