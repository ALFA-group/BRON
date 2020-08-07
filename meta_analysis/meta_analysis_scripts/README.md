# How to Use Meta Analysis Scripts

The following scripts are available to perform meta-analyses using BRON:
* count_bron_contents.py
* cve_connectivity_by_year.py
* cve_data_helper.py
* data_types_over_versions.py
* make_edge_distributions.py
* vendor_applications.py
* vendor_tactic_and_cvss.py
* vendor_threat_data_types.py


#### count_bron_contents.py
This script counts the connections between data types.

Before you run the script, you will need:
* Data summaries for all data types using make_data_summary.py
* A folder (e.g. data_summary_folder) containing subfolders of the data summaries

It is important for the folder containing subfolders to have the following subfolder names:
```
* data_summary_folder
    * all_cves_all_versions
    * recent_cves_all_versions
    * all_cves_latest_version
    * recent_cves_latest_version
```

Each of the subfolders should contain data summaries for all data types:
```
* all_cves_all_versions
    * tactic_summary.csv
    * technique_summary.csv
    * capec_summary.csv
    * cwe_summary.csv
    * cve_summary.csv
    * cpe_summary.csv
```

Arguments in the script:
* `data_summary_folder_path`: Path to folder containing subfolders of the data summaries
* `all_versions` (optional): True if you want to use all versions of Affected Platform Configurations, False if you want to use only latest version of Affected Platform Configurations
* `all_years` (optional): True if you want to use CVE data from all years, False if you want to use CVE data from only 2015-2020

Example on the command line:
```
python meta_analysis/meta_analysis_scripts/count_bron_contents.py --data_summary_folder_path data/meta_analysis/data_summary_folder --all_versions --all_years
```


#### cve_connectivity_by_year.py
This script plots the number and percentage of Vulnerabilities connected to a Tactic, Attack Pattern, or Weakness.

Before you run the script, you will need:
* A comma-delimited string containing years
* Path search results for each year using path_search_BRON_db.py
* A folder containing the path search results
* A PNG file to save your new figure

It is important for the path search results for a given year (e.g. 2020) to be named as `search_result_cve_2020.csv`.

Arguments in the script:
* `years`: Comma-delimited string containing years
* `search_result_folder_path`: Path to folder with search results for selected years
* `number_or_percent`: 'number' plots occurrence of Vulnerabilities over years, while 'percent' plots fraction of Vulnerabilities over years
* `save_path`: Path to PNG file to save your new figure

Example on the command line:
```
python meta_analysis/meta_analysis_scripts/cve_connectivity_by_year.py --years 2018,2019,2020 --search_result_folder_path data/search_results --number_or_percent number --save_path data/figures/cve_connectivity.png
```


#### cve_data_helper.py
This script plots a line plot of CVSS scores by year or a density plot of CVSS scores.

Before you run the script, you will need:
* A comma-delimited string containing years
* Data summaries for all data types using make_data_summary.py
* A folder (e.g. data_summary_folder) containing subfolders of the data summaries (refer to instructions under count_bron_contents.py for organizing subfolders)
* A PNG file to save your new figure

Arguments in the script:
* `years`: Comma-delimited string containing years
* `data_summary_folder_path`: Path to folder containing subfolders of the data summaries
* `plot_type`: Type of plot that you want to create, either a 'line-plot' of CVSS scores by year or a 'density-plot' of CVSS scores
* `save_path`: Path to PNG file to save your new figure

Example on the command line:
```
python meta_analysis/meta_analysis_scripts/cve_data_helper.py --years 2018,2019,2020 --data_summary_folder_path data/meta_analysis/data_summary_folder --plot_type line-plot --save_path data/figures/line_plot.png
```


#### data_types_over_versions.py
This script plots the number of data types for a specific vendor product over all product versions.

Before you run the script, you will need:
* A JSON file containing BRONdb
* A CSV file to save path search starting points
* Another CSV file to save path search results
* A PNG file to save your new figure

Arguments in the script:
* `db_path`: Path to JSON file containing BRONdb
* `vendor`: A specific vendor
* `product`: A specific product by the selected vendor
* `starting_point_file`: Path to CSV file to save path search starting points
* `search_result_file`: Path to CSV file to save path search results
* `save_path`: Path to PNG file to save your new figure

Example on the command line:
```
python meta_analysis/meta_analysis_scripts/data_types_over_versions.py --db_path data/graph/graph_results/threat_data.json --vendor ibm --product business_process_manager --starting_point_file data/starting_point.csv --search_result_file data/search_results/search_result.csv --save_path data/figures/data_types_over_versions.png
```


#### make_edge_distributions.py
This script plots the number of edges for a specific data type.

Before you run the script, you will need:
* Data summaries for all data types using make_data_summary.py
* A folder (e.g. data_summary_folder) containing subfolders of the data summaries (refer to instructions under count_bron_contents.py for organizing subfolders)
* A PNG file to save your new figure

Arguments in the script:
* `data_summary_folder_path`: Path to folder containing subfolders of the data summaries
* `data_type`: Either 'tactic', 'technique', 'capec', 'cwe', 'cve', or 'cpe'
* `save_path`: Path to PNG file to save your new figure

Example on the command line:
```
python meta_analysis/meta_analysis_scripts/make_edge_distributions.py --data_summary_folder_path data --data_type tactic --save_path data/figures/tactic_edges.png
```


#### vendor_applications.py
This script plots the number of Affected Platform Configurations for different vendors.

Before you run the script, you will need:
* CPE summary CSV files using make_data_summary.py when all versions and only latest version of Affected Platform Configurations are used
* A PNG file to save your new figure

Arguments in the script:
* `cpe_summary_all_versions_path`: Path to CSV file containing CPE summary when all versions of Affected Platform Configurations are used
* `cpe_summary_latest_version_path`: Path to CSV file containing CPE summary when only latest version of Affected Platform Configurations are used
* `save_path`: Path to PNG file to save your new figure

Example on the command line:
```
python meta_analysis/meta_analysis_scripts/vendor_applications.py --cpe_summary_all_versions_path data/meta_analysis/cpe_summary_all_versions.csv --cpe_summary_latest_version_path data/meta_analysis/cpe_summary_latest_version.csv
```


#### vendor_tactic_and_cvss.py
This script plots a heatmap or violinplot of different tactics and vendors. The heatmap shows the number of unique products of each vendor affected by each tactic. The violinplot can show the CVSS scores of products of each vendor affected by either all tactics or two specific tactics for comparison.

Before you run the script, you will need:
* A file containing path search results for selected tactics
* Path search results for each vendor using path_search_BRON_db.py
* A folder containing the path search results for vendors
* A file containing the CVE data summary when using all CVE years and all versions of Affected Platform Configurations
* A PNG file to save your new figure

Arguments in the script:
* `tactics`: Comma-delimited string containing tactic names, e.g. discovery,defense-evasion
* `vendors`: Comma-delimited string containing vendor names, e.g. ibm,mozilla
* `tactic_search_result_file`: Path to file with search result for selected tactics
* `vendor_search_result_folder`: Path of folder with search results for selected vendors
* `plot_type`: Either 'heatmap', 'violinplot', or 'two-tactic-violinplot'
* `violin_stick`: True if you want to add sticks to violinplot
* `cve_summary_path`: Path to file containing the CVE data summary
* `save_path`: Path to PNG file to save your new figure


#### vendor_threat_data_types.py
This script plots the number of each data type for specific vendors.

Before you run the script, you will need:
* A comma-delimited string containing vendor names
* Path search results for each vendor using path_search_BRON_db.py
* A folder containing the path search results
* A PNG file to save your new figure

It is important for the path search results for a given vendor (e.g. IBM) to be named as `search_result_ibm.csv`.

Arguments in the script:
* `vendors`: Comma-delimited string containing vendor names
* `search_result_folder_path`: Path to folder containing the path search results
* `save_path`: Path to PNG file to save your new figure

Example on the command line:
```
python meta_analysis/meta_analysis_scripts/vendor_threat_data_types.py --vendors ibm,mozilla --search_result_folder_path data/search_results --save_path data/figures/vendor_threat_data_types.png
```
