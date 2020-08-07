# bron_framework
BRON framework cyber hunting

### BRON_db
The different types of threat data can be linked together in a graph-based format called BRON_db. To create a new BRON_db using input threat data, run the following command:
```
python BRON_db/build_BRON_db.py --data_folder DATA_FOLDER --save_path FILE_NAME --only_recent_cves (optional)
```
`DATA_FOLDER` is the folder path of input data, and `FILE_NAME` is the file path to save BRON_db. To make BRON_db using only recent CVEs, add the argument `--only_recent_cves`. An example BRON_db using input threat data in the example_data folder can be found in `data/BRON_db.json`.

### Structure of BRON_db
Each entry of threat data is a node in BRON_db and has 4 attributes. The node has a unique name in BRON_db that is of the form (threat data type)\_(unique 5 digit id) where the threat data type is either tactic, technique, capec, cwe, cve, cpe, or network-node.

Additionally, there are four attributes for each node:
- Original_id: ID of threat data in MITRE/NIST if it exists
- Datatype: One of tactic, technique, capec, cwe, cve, cpe, or network-node
- Name: Name of threat data in MITRE/NIST if exists
- Metadata: Any additional information that is contained in MITRE/NIST
