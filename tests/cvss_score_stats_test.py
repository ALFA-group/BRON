import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import json
import csv
import statistics
import random
import pylab
import scipy.stats as stats
import math
import matplotlib.colors
from matplotlib.patches import Patch
import argparse
import sys
from typing import List, Dict, Any

"""
Statistical significance test for CVSS scores by year and Vulnerability type
"""

VULNERABILITY_LABELS = ['All Vulnerabilities', 'Tactic Path', 'Attack Pattern Path', 'Weakness Path', 'Unlinked Vulnerability']
YEARS_TO_USE = ['2006', '2007', '2008', '2009', '2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020']

def mann_whitney_test(sample_data):
    all_vulnerabilities_samples, tactic_path_samples, attack_pattern_path_samples, weakness_path_samples, unlinked_vulnerability_samples = sample_data
    p_values = [[[100 for col in range(5)] for row in range(5)] for k in range(len(YEARS_TO_USE)-1)]
    for k in range(len(YEARS_TO_USE)-1):
        year1 = YEARS_TO_USE[k]
        year2 = YEARS_TO_USE[k+1]
        all_cve1 = all_vulnerabilities_samples[year1]
        tactic1 = tactic_path_samples[year1]
        capec1 = attack_pattern_path_samples[year1]
        cwe1 = weakness_path_samples[year1]
        not_connected1 = unlinked_vulnerability_samples[year1]
        all_cve2 = all_vulnerabilities_samples[year2]
        tactic2 = tactic_path_samples[year2]
        capec2 = attack_pattern_path_samples[year2]
        cwe2 = weakness_path_samples[year2]
        not_connected2 = unlinked_vulnerability_samples[year2]
        year1_samples = [all_cve1, tactic1, capec1, cwe1, not_connected1]
        year2_samples = [all_cve2, tactic2, capec2, cwe2, not_connected2]
        for row in range(len(year1_samples)):
            for col in range(len(year2_samples)):
                test_statistic, p_value = stats.mannwhitneyu(year1_samples[row], year2_samples[col], alternative='two-sided')
                p_values[k][row][col] = p_value
    return p_values


def p_value_heatmap(sample_data, save_path):
    p_values = mann_whitney_test(sample_data)
    fig, ((ax1, ax2, ax3, ax4, ax5), (ax6, ax7, ax8, ax9, ax10), (ax11, ax12, ax13, ax14, ax15)) = plt.subplots(3, 5, figsize=(30,20), sharex=True, sharey=True)
    axes = [ax1, ax2, ax3, ax4, ax5, ax6, ax7, ax8, ax9, ax10, ax11, ax12, ax13, ax14, ax15]
    colors = [[0.0, "#03051b"], [0.05, "#03051b"], [0.050000000001, "#fdebdb"], [1.0, "#fdebdb"]]
    cmap = matplotlib.colors.LinearSegmentedColormap.from_list("", colors)
    for i in range(len(YEARS_TO_USE)-1):
        year1 = YEARS_TO_USE[i]
        year2 = YEARS_TO_USE[i+1]
        year_array = np.array(p_values[i])
        labels = np.asarray([[round(year_array[row, col], 4) if round(year_array[row, col], 4) <= 0.05 else ">0.05" for col in range(5)] for row in range(5)])
        heatmap = sns.heatmap(year_array, cmap=cmap, square=True, cbar=False, xticklabels=VULNERABILITY_LABELS, yticklabels=VULNERABILITY_LABELS, annot=labels, fmt='', ax=axes[i])
        heatmap.set_xticklabels(heatmap.get_xticklabels(), rotation=45, horizontalalignment='right')
        heatmap.set_title(f"{year1}-{year2}")
        heatmap.set_ylabel(f"{year1}")
        heatmap.set_xlabel(f"{year2}")
    bottom, top = ax14.get_ylim()
    ax14.set_ylim(bottom+0.5, top-0.5)
    ax15.set_visible(False)
    fig.legend(handles=[Patch(facecolor="#03051b", label='p-value ≤ 0.05'), Patch(facecolor="#fdebdb", label='p-value > 0.05')], loc='right')
    fig.tight_layout()
    fig.subplots_adjust(right=0.94)
    fig.savefig(save_path)


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Statistical significance test for CVSS scores by year and Vulnerability type")
    parser.add_argument('--all_vulnerabilities', type=str, required=True,
                        help='Path to JSON file containing samples of CVSS scores by year for All Vulnerabilities')
    parser.add_argument('--tactic_path', type=str, required=True,
                        help='Path to JSON file containing samples of CVSS scores by year for Vulnerabilities with Tactic Path')
    parser.add_argument('--attack_pattern_path', type=str, required=True,
                        help='Path to JSON file containing samples of CVSS scores by year for Vulnerabilities with Attack Pattern Path')
    parser.add_argument('--weakness_path', type=str, required=True,
                        help='Path to JSON file containing samples of CVSS scores by year for Vulnerabilities with Weakness Path')
    parser.add_argument('--unlinked_vulnerability', type=str, required=True,
                        help='Path to JSON file containing samples of CVSS scores by year for Unlinked Vulnerabilities')
    parser.add_argument('--save_path', type=str, required=True, help='Path to save figure')
    args = vars(parser.parse_args())
    return args


def main(**args: Dict[str, Any]) -> None:
    all_vulnerabilities, tactic_path, attack_pattern_path, weakness_path, unlinked_vulnerability, save_path = args.values()
    with open(all_vulnerabilities) as f:
        all_vulnerabilities_samples = json.load(f)
    with open(tactic_path) as f:
        tactic_path_samples = json.load(f)
    with open(attack_pattern_path) as f:
        attack_pattern_path_samples = json.load(f)
    with open(weakness_path) as f:
        weakness_path_samples = json.load(f)
    with open(unlinked_vulnerability) as f:
        unlinked_vulnerability_samples = json.load(f)
    sample_data = [all_vulnerabilities_samples, tactic_path_samples, attack_pattern_path_samples, weakness_path_samples, unlinked_vulnerability_samples]
    p_value_heatmap(sample_data, save_path)


if __name__ == "__main__":
    kwargs = parse_args(sys.argv[1:])
    main(**kwargs)
