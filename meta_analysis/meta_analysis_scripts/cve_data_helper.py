import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import matplotlib as mpl
from matplotlib.ticker import (MultipleLocator, FormatStrFormatter, AutoMinorLocator)
import numpy as np
import ast
import seaborn as sns
from collections import Counter
import argparse
import os
import sys
from typing import List, Dict, Any

"""
Plot line plot of CVSS scores by year or density plot of CVSS scores
"""

def make_line_plot(data_dict_1, data_dict_2, years, save_path=None):
    plt.rc('font', size=14)
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"
    y_vals_1 = []
    y_vals_2 = []
    for year in years:
        y_vals_1.append(data_dict_1[year])
        y_vals_2.append(data_dict_2[year])
    fig, ax = plt.subplots()
    ax.plot(years, y_vals_1, color='darkviolet', marker='o')
    ax.plot(years, y_vals_2, '--', color='tab:purple', marker='P')
    blue_line = mlines.Line2D([], [], color='darkviolet', marker='o', label="Annual Total Severity")
    orange_line = mlines.Line2D([], [], color='tab:purple', linestyle='--', marker='P', label="Non-demonstrated Severity")
    plt.legend(handles=[blue_line, orange_line], fontsize=12)
    plt.xlabel("Year")
    plt.ylabel("Sum of CVSS Scores")
    plt.xticks(rotation=45)
    # ax.set_xticks(ax.get_xticks()[::2])
    # ax.xaxis.set_minor_locator(AutoMinorLocator(2))
    ax.yaxis.set_major_formatter(mpl.ticker.StrMethodFormatter('{x:,.0f}'))
    ax.tick_params(which='both', width=2)
    ax.tick_params(which='major', length=7)
    ax.tick_params(which='minor', length=4)
    plt.ylim(top=1000) # change this value to adjust y-axis limit
    plt.tight_layout()
    if save_path is None:
        plt.show()
    else:
        plt.savefig(save_path, dpi=400)


def line_plot_cvss_scores_by_year(data_summary_folder_path, years, save_path=None):
    """
    Look at the percentage of floating risk by year
    :return:
    """
    floating_risk = {}
    total_risk = {}
    df = pd.read_csv(os.path.join(data_summary_folder_path, "all_cves_all_versions/cve_summary.csv"))
    for index, row in df.iterrows():
        metadata = row['metadata']
        row_dict = ast.literal_eval(metadata)
        risk_score = int(row_dict['weight'])
        cwe_edges = row['Number of Edges Connected to cwe']
        cpe_edges = row['Number of Edges Connected to cpe']
        orign_id = row['original_id']
        year = orign_id.split('-')[1]
        if cwe_edges + cpe_edges == 0:
            if year not in floating_risk:
                floating_risk[year] = risk_score
            else:
                floating_risk[year] += risk_score
        if year not in total_risk:
            total_risk[year] = risk_score
        else:
            total_risk[year] += risk_score
    make_line_plot(total_risk, floating_risk, years, save_path=save_path)


def density_plot_cvss_scores(data_summary_folder_path, save_path=None):
    plt.rc('font', size=14)
    plt.rcParams["font.weight"] = "bold"
    plt.rcParams["axes.labelweight"] = "bold"
    df_1 = pd.read_csv(os.path.join(data_summary_folder_path, "all_cves_all_versions/cve_summary.csv"))
    df_2 = pd.read_csv(os.path.join(data_summary_folder_path, "recent_cves_all_versions/cve_summary.csv"))
    df_list = [df_1, df_2]
    floating_all = []
    floating_recent = []
    total_all = []
    total_recent = []
    floating_dict_list = [floating_all, floating_recent]
    total_risk_dict_list = [total_all, total_recent]
    for i, df in enumerate(df_list):
        floating_dict = floating_dict_list[i]
        total_risk_dict = total_risk_dict_list[i]
        for index, row in df.iterrows():
            metadata = row['metadata']
            row_dict = ast.literal_eval(metadata)
            risk_score = row_dict['weight']
            cwe_edges = row['Number of Edges Connected to cwe']
            cpe_edges = row['Number of Edges Connected to cpe']
            if cwe_edges + cpe_edges == 0:
                floating_dict.append(risk_score)
            total_risk_dict.append(risk_score)
    connected_all = list((Counter(total_all) - Counter(floating_all)).elements())
    connected_recent = list((Counter(total_recent) - Counter(floating_recent)).elements())
    fig, ax = plt.subplots()
    sns.distplot(connected_all, hist=False, kde=True, kde_kws = {'linewidth': 2}, label='Operational Severity, All Vulnerabilities')
    sns.distplot(floating_all, hist=False, kde=True, kde_kws = {'linewidth': 2, 'linestyle': '--'}, label='Non-demonstrated Severity, All Vulnerabilities')
    sns.distplot(connected_recent, hist=False, kde=True, kde_kws = {'linewidth': 2, 'linestyle': '-.'}, label='Operational Severity, Recent Vulnerabilities')
    sns.distplot(floating_recent, hist=False, kde=True, kde_kws = {'linewidth': 2, 'linestyle': ':'}, label='Non-demonstrated Severity, Recent Vulnerabilities')
    plt.legend(fontsize=11)
    plt.xlabel('CVSS Score')
    plt.ylabel('Density')
    ax.xaxis.set_minor_locator(AutoMinorLocator(2))
    ax.tick_params(which='both', width=2)
    ax.tick_params(which='major', length=7)
    ax.tick_params(which='minor', length=4)
    plt.xlim(0, 10)
    plt.ylim(0, 0.5)
    plt.tight_layout()
    if save_path is None:
        plt.show()
    else:
        plt.savefig(save_path, dpi=400)


def parse_args(args: List[str]) -> Dict[str, Any]:
    parser = argparse.ArgumentParser(description="Plot sum of CVSS scores by year or density of CVSS scores")
    parser.add_argument('--years', type=str, required=True,
                        help='Comma-delimited string containing years, e.g. 2018,2019,2020')
    parser.add_argument('--data_summary_folder_path', type=str, required=True,
                        help='Path to folder containing subfolders of data summaries for all data types')
    parser.add_argument('--plot_type', type=str, required=True,
                        help='Either line-plot or density-plot')
    parser.add_argument('--save_path', type=str, required=True, help='Path to save figure')
    args = vars(parser.parse_args())
    return args


def main(**args: Dict[str, Any]) -> None:
    years, data_summary_folder_path, plot_type, save_path = args.values()
    years_split = years.split(',')
    if plot_type == "line-plot":
        line_plot_cvss_scores_by_year(data_summary_folder_path, years_split, save_path=save_path)
    elif plot_type == "density-plot":
        density_plot_cvss_scores(data_summary_folder_path, save_path=save_path)
    else:
        print("Error: plot_type must be either line-plot or density-plot")


if __name__ == "__main__":
    kwargs = parse_args(sys.argv[1:])
    main(**kwargs)
