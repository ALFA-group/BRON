##### Parsed MITRE NIST Data
- applications_cpe.json: Contains mapping of applications to cpes 
- capec_map_to_mitre_matrix.json: Contains mapping of CAPECs to ATT&CK matrix ID 
- capec_cwe_mapping: Contains mapping of CAPECs to cwes
- cwe_names.json: Contains mapping of cwes to cwe names
- capec_names.json: Contains mapping of CAPEC number to actual name 
- cve_map_to_score_cwe_application.json: Contains mapping from CVE ID to CVE Score, CWEs and applications (under 'Vendors')
- techique_name_map.json: Contains mapping of Technique ID to Technique name
- technique_tactic_map.json: Contains mapping of Technique IDs to Tactic names
##### Links to original data
The data in the following files originated from https://github.com/mitre/cti/blob/master/enterprise-attack/enterprise-attack.json:
  - technique_name_map.json
  - technique_tactic_map.json
  - capec_map_to_mitre_matrix.json
 
 The data in the following files originated from came from the CSV version of this file https://capec.mitre.org/data/definitions/3000.html:
 - capec_names.json
 
 The data in the following files originated from this link https://cwe.mitre.org/data/downloads.html under the heading Navigate CWE
 and under Research Concepts (csv zip file):
 - capec_cwe_mapping.json
 - cwe_names.json
 
 The data in the following files originated from: https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019.json.zip 
 - cve_map_to_score_cwe_applications.json
 - applications_cpe.json
