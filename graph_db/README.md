# BRON in a graph DB

## Requirements

- Build BRON, so there exists a `BORN.json` file

- Install ArangoDB https://www.arangodb.com/download-major/

## Setup

- Create arango files to import
```
python bron_arango.py -f ${PATH_TO_BRON_JSON}
# Expected output
Done: tactic-technique                                                                   
Done: technique-capec                                                                    
Done: capec-cwe                                                                          
Done: cwe-cve                                                                            
Done: cve-cpe                                                                            
Done: technique-tactic                                                                   
Done: capec-technique                                                                    
Done: cwe-capec                                                                          
Done: cve-cwe                                                                            
Done: cpe-cve                                                                            
Done: tactic                                                                             
Done: technique                                                                          
Done: capec                                                                              
Done: cwe                                                                                
Done: cve                                                                                
Done: cpe                                                                                
Loaded nx
Done: Nodes
Done: Edges
# Check files are created
ls *json
capec-cwe.json        capec.json    cpe.json      cve-cwe.json  cwe-capec.json  cwe.json               tactic.json           technique-tactic.json
capec-technique.json  cpe-cve.json  cve-cpe.json  cve.json      cwe-cve.json    tactic-technique.json  technique-capec.json  technique.json
```

- Import into arrango
```
python bron_arango.py --arango_import
# Expected output
Connected to ArangoDB 'http+tcp://127.0.0.1:8529, version: 3.6.9, database: 'BRON', username: 'root'
----------------------------------------
database:               BRON
collection:             tactic-technique
create:                 yes
create database:        no
source filename:        tactic-technique.json
file type:              jsonl
threads:                2
connect timeout:        5
request timeout:        1200
----------------------------------------
Starting JSON import...
2020-12-07T21:53:02Z [289565] INFO [9ddf3] processed 32767 bytes (3%) of input file
2020-12-07T21:53:02Z [289565] INFO [9ddf3] processed 65534 bytes (47%) of input file
2020-12-07T21:53:02Z [289565] INFO [9ddf3] processed 73625 bytes (92%) of input file

created:          589
warnings/errors:  0
updated/replaced: 0
ignored:          0
Connected to ArangoDB 'http+tcp://127.0.0.1:8529, version: 3.6.9, database: 'BRON', username: 'root'
----------------------------------------
database:               BRON
collection:             cwe-cve
create:                 yes
create database:        no
source filename:        cwe-cve.json
file type:              jsonl
threads:                2
connect timeout:        5
request timeout:        1200
...
```

## Run a query

```bash
python graph_db/query_graph_db.py --starting_point_type capec --starting_point example_data/example_input_data/starting_point_capec.csv
# Expected output is a dictionary of starting point as key and the value is a dictionary of number of connections to the data type from the starting point
{'125': defaultdict(<class 'int'>, {'cwe': 2, 'technique': 1}), '640': defaultdict(<class 'int'>, {'technique': 1}), '13': defaultdict(<class 'int'>, {'cwe': 10, 'technique': 2})}
```

