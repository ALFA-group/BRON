# BRON - Link and evaluate public threat data for Cyber Hunting

Threat data from [MITRE ATT&CK](https://attack.mitre.org/), [CAPEC](https://capec.mitre.org/), [CWE](https://cwe.mitre.org/) and [CVE](https://nvd.nist.gov) data sources are linked together in a graph called BRON. The data types are linked with bidirectional edges in the following manner:
```
Tactic <--> Technique <--> Attack Pattern <--> Weekness <--> Vulnerability <--> Affected Product Configuration
```

## Installation

- Python version > = 3.8
- Run `pip install -r requirements.txt` to install requirements

## Getting Started with Tutorials
Four tutorials are available in the `tutorials` folder on the following topics:
- How to download and parse the threat data used for BRON (`download_threat_data_tutorial.ipynb`)
- How to build BRON and find paths in BRON (`bron_tutorial.ipynb`)
- How to build the full BRON and find paths in BRON (`full_bron.ipynb`)
- How to perform meta-analyses using BRON (`meta_analysis_tutorial.ipynb`)
- How to perform extra meta-analyses using BRON (`extra_meta_analysis_tutorial.ipynb`)

These tutorials include example code and outputs using data in the `example_data` folder.

## Usage
```
usage: build_BRON.py [-h] --input_data_folder INPUT_DATA_FOLDER --save_path SAVE_PATH [--only_recent_cves]

Create BRON graph from threat data

optional arguments:
  -h, --help            show this help message and exit
  --input_data_folder INPUT_DATA_FOLDER
                        Folder path to input threat data
  --save_path SAVE_PATH
                        Folder path to save BRON graph and files, e.g. example_data/example_output_data
  --only_recent_cves    Make BRON with CVEs from 2015 to 2020 only
```

An example BRON with its input threat data can be found in the `example_data` folder.

## Structure of BRON
Each entry of threat data is a node in BRON that has 4 attributes. The node has a unique name in BRON of the form (threat data type)\_(unique 5 digit id) where the threat data type is either Tactic, Technique, CAPEC, CWE, CVE, or Affected Product Configuration (sometimes called CPE).

There are 4 attributes for each node:
- Original_id: ID of threat data in MITRE/NIST if it exists
- Datatype: One of Tactic, Technique, CAPEC, CWE, CVE, or CPE
- Name: Name of threat data in MITRE/NIST if it exists
- Metadata: Any additional information that is contained in MITRE/NIST

## Bibliography

```
TBD
```

