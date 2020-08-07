import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib as mpl
from matplotlib.ticker import (MultipleLocator, FormatStrFormatter, AutoMinorLocator)
import seaborn as sns
from collections import Counter
import csv
import argparse
import sys
from typing import List, Dict, Any
from ast import literal_eval

"""
Plot number of Affected Platform Configurations for different vendors
"""

def make_vendor_to_cpes(cpe_summary):
    df = pd.read_csv(cpe_summary, usecols=["metadata", "original_id"])
    vendor_to_cpes = dict() # maps vendor to set of CPE IDs
    for row_index in df.index:
        cpe_id = df["original_id"][row_index]
        metadata = literal_eval(df["metadata"][row_index])
        vendor = metadata["vendor"]
        if vendor not in vendor_to_cpes:
            vendor_to_cpes[vendor] = set()
        vendor_to_cpes[vendor].add(cpe_id)
    return vendor_to_cpes


def make_vendor_to_num_cpes(vendor_to_cpes):
    vendor_to_num_cpes = dict()
    for vendor, cpes in vendor_to_cpes.items():
        num_cpes = len(cpes)
        vendor_to_num_cpes[vendor] = num_cpes
    return vendor_to_num_cpes


def top_n_vendors(vendor_to_num_cpes, n=5): # n is int for top n, default is top 5
    counter = Counter(vendor_to_num_cpes)
    top_n_tuple = counter.most_common(n)
    top_n = dict()
    for vendor, num_cpes in top_n_tuple:
        top_n[vendor] = num_cpes
    print(f"Top {str(n)} vendors by number of applications: ", top_n)
    return top_n


def vendor_num_apps_histogram(all_versions, latest_versions, save_path=None):
    plt.rc('font', size=14)
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"
    set_bins = np.linspace(min(all_versions), max(all_versions), num=13)
    bin_width = 10
    all_versions_color = "darkturquoise"
    latest_versions_color = "cyan"
    x_vals = 0.5*(set_bins[1:]+set_bins[:-1]) - 0.5*bin_width
    x_vals_2 = 0.5*(set_bins[1:]+set_bins[:-1]) + 0.5*bin_width
    all_versions_counts, _ = np.histogram(all_versions, bins=set_bins)
    latest_versions_counts, _ = np.histogram(latest_versions, bins=set_bins)
    ax_1 = plt.subplot(1,1,1)
    bar_1 = ax_1.bar(x_vals, all_versions_counts, width=bin_width, color=all_versions_color, edgecolor='black', hatch='OO')
    bar_2 = ax_1.bar(x_vals_2, latest_versions_counts, width=bin_width, color=latest_versions_color, edgecolor='black', hatch='..')
    plt.legend([bar_1, bar_2], ['All Versions', 'Latest Version'])
    plt.yscale('log')
    plt.xlim(right=200) # change this value to adjust x-axis limit
    ax_1.xaxis.set_major_formatter(mpl.ticker.StrMethodFormatter('{x:,.0f}'))
    ax_1.xaxis.set_minor_locator(AutoMinorLocator(5))
    ax_1.tick_params(which='both', width=2)
    ax_1.tick_params(which='major', length=7)
    ax_1.tick_params(which='minor', length=4)
    plt.locator_params(axis='x', nbins=6)
    plt.xlabel("Number of Affected Platform Configurations")
    plt.ylabel("Frequency (log)")
    plt.tight_layout()
    if save_path is None:
        plt.show()
    else:
        plt.savefig(save_path, dpi=400)


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Plot number of Affected Platform Configurations for different vendors")
    parser.add_argument('--cpe_summary_all_versions_path', type=str, required=True,
                        help='Path to cpe_summary.csv file when using all versions of Affected Platform Configurations')
    parser.add_argument('--cpe_summary_latest_version_path', type=str, required=True,
                        help='Path to cpe_summary.csv file when using only latest version of Affected Platform Configurations')
    parser.add_argument('--save_path', type=str, required=True, help='Path to save figure')
    args = vars(parser.parse_args())
    return args


def main(**args: Dict[str, Any]) -> None:
    cpe_summary_all_versions, cpe_summary_latest_version, save_path = args.values()
    vendor_to_cpes = make_vendor_to_cpes(cpe_summary_all_versions)
    vendor_to_num_cpes = make_vendor_to_num_cpes(vendor_to_cpes)
    num_cpes = list(vendor_to_num_cpes.values())
    vendor_to_cpes_versioning = make_vendor_to_cpes(cpe_summary_latest_version)
    vendor_to_num_cpes_versioning = make_vendor_to_num_cpes(vendor_to_cpes_versioning)
    num_cpes_versioning = list(vendor_to_num_cpes_versioning.values())
    vendor_num_apps_histogram(num_cpes, num_cpes_versioning, save_path=save_path)


if __name__ == "__main__":
    kwargs = parse_args(sys.argv[1:])
    main(**kwargs)
