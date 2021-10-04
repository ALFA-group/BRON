# BRON - Link and evaluate public threat data for Cyber Hunting

Threat data from [MITRE ATT&CK](https://attack.mitre.org/), [CAPEC](https://capec.mitre.org/), [CWE](https://cwe.mitre.org/) and [CVE](https://nvd.nist.gov) data sources are linked together in a graph called BRON. The data types are linked with bidirectional edges in the following manner:
```
Tactic <--> Technique <--> Attack Pattern <--> Weakness <--> Vulnerability <--> Affected Product Configuration
```
## Deployment
See [graph_db](graph_db) for a public instance of graph data base implementaion [bron.alfa.csail.mit.edu](http://bron.alfa.csail.mit.edu:8529)

Pre-requisites:
- Docker ([installing Docker](https://docs.docker.com/engine/install/))
- Docker Compose ([installing Compose](https://docs.docker.com/compose/install/))

To deploy BRON on top of ArangoDB, clone this repository and run:
```
docker-compose up -d
```

The deployment starts two containers:
- `brondb`: an ArangoDB server hosting the BRON graph and collections
- `bootstrap`: an ephemeral container that builds BRON and loads it into the graph database

It may take a few minutes for the bootstrap to conclude. It will download and analyze the required datasets, build BRON, and import it into the database. You can check its completion by monitoring the `bootstrap` container logs.
```
docker logs -f bootstrap
```
To access the graph database console, point your browser to `http://localhost:8529`, login, and select BRON as database. 

> Note: this deployment uses docker secrets for setting the database password; its value can be changed in `./graph_db/arango_root_password`.

## Programmatic APIs Installation

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

arXiv report: [https://arxiv.org/abs/2010.00533](https://arxiv.org/abs/2010.00533)

```
@misc{hemberg2021linking,
      title={Linking Threat Tactics, Techniques, and Patterns with Defensive Weaknesses, Vulnerabilities and Affected Platform Configurations for Cyber Hunting}, 
      author={Erik Hemberg and Jonathan Kelly and Michal Shlapentokh-Rothman and Bryn Reinstadler and Katherine Xu and Nick Rutar and Una-May O'Reilly},
      year={2021},
      eprint={2010.00533},
      archivePrefix={arXiv},
      primaryClass={cs.CR}
}
```

