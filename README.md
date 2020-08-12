# BRON Framework for Cyber Hunting

### BRON
The different types of threat data are linked together in a graph called BRON. The data types are linked with bidirectional edges in the following manner:
```
Tactic <--> Technique <--> CAPEC <--> CWE <--> CVE <--> CPE
```
To create a new BRON using input threat data, run the following command:
```
python BRON/build_BRON.py --input_data_folder INPUT_DATA_FOLDER --save_path SAVE_PATH --only_recent_cves (optional)
```
`INPUT_DATA_FOLDER` is the folder path to input threat data, and `SAVE_PATH` is the folder path to save the BRON graph and files. To make BRON using only recent CVEs, add the argument `--only_recent_cves`. An example BRON with its input threat data can be found in the `example_data` folder.

### Structure of BRON
Each entry of threat data is a node in BRON that has 4 attributes. The node has a unique name in BRON of the form (threat data type)\_(unique 5 digit id) where the threat data type is either Tactic, Technique, CAPEC, CWE, CVE, or CPE.

There are 4 attributes for each node:
- Original_id: ID of threat data in MITRE/NIST if it exists
- Datatype: One of Tactic, Technique, CAPEC, CWE, CVE, or CPE
- Name: Name of threat data in MITRE/NIST if it exists
- Metadata: Any additional information that is contained in MITRE/NIST

### Technologies
- Python version 3.8
- Run `pip install -r requirements.txt` to install requirements

### Getting Started with Tutorials
Four tutorials are available in the `tutorials` folder on the following topics:
- How to download and parse the threat data used for BRON (`download_threat_data_tutorial.ipynb`)
- How to build BRON and find paths in BRON (`bron_tutorial.ipynb`)
- How to perform meta-analyses using BRON (`meta_analysis_tutorial.ipynb`)
- How to perform extra meta-analyses using BRON (`extra_meta_analysis_tutorial.ipynb`)

These tutorials include example code and outputs using data in the `example_data` folder.
