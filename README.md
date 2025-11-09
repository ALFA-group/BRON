[![BRON](docs/figures/bron-logo.png)](docs/figures/brom-logo.png)

# BRON - Link and evaluate public threat and mitigation data for Cyber Hunting

**TODO** update figures

[![BRON February 2023](docs/figures/BRON_drawing.png)](docs/figures/BRON_drawing.png)

Threat data from [MITRE ATT&CK](https://attack.mitre.org/), [CAPEC](https://capec.mitre.org/), [CWE](https://cwe.mitre.org/) , [CVE](https://nvd.nist.gov), [MITRE Engage](https://engage.mitre.org/), [MITRE D3FEND](https://d3fend.mitre.org/), [MITRE CAR](https://car.mitre.org/) , [MITRE ATLAS](https://atlas.mitre.org/) data sources are linked together in a graph called BRON. The data types are linked with bidirectional edges. 

## Deployment
See [graph_db](graph_db) for a public instance of graph data base implementaion [bron.alfa.csail.mit.edu](http://bron.alfa.csail.mit.edu:8529)

### Ubuntu
```
# Python 
sudo apt install python3 pyhton3-venv python3-dev
# Arango
curl -OL https://download.arangodb.com/arangodb310/DEBIAN/Release.key
sudo apt-key add - < Release.key
echo 'deb https://download.arangodb.com/arangodb310/DEBIAN/ /' | sudo tee /etc/apt/sources.list.d/arangodb.list
sudo apt-get install apt-transport-https
sudo apt-get update
sudo apt-get install arangodb3=3.12.4

# Python venv
python3 -m venv ~/.venvs/BRON-dev
# Activate venv
source ~/.venvs/BRON-dev/bin/activate
# Pythonpath
export PYTHONPATH=.

# BRON environment variables
export BRON_PWD={The password you set when you installed arango}
export BRON_SERVER_IP=127.0.0.1
```

Build BRON
```
python3 tutorials/build_bron.py --username=root --password=${BRON_PWD} --ip=${BRON_SERVER_IP}
```

Test
```
python -m unittest tests.test_bron_graph_db
```

### Docker
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

Python version > = 3.8

### Pip
- Create a `pip` environment
```
python3 -m venv bron_venv
source ./bron_venv/bin/activate
pip install -r requirements.txt
```

## Getting Started 

Build BRON on localhost (requires an arangodb installation)
```
python tutorials/build_bron.py --username root --password $(cat arango_root_password) --ip 127.0.0.1
tail -n 1 build_bron.log
```

This should produce a `build_bron.log` file that ends with `END building BRON`.

## Tutorials
Tutorials are available in the `tutorials` folder 


## Usage
```
usage: build_bron.py [-h] --username USERNAME --password PASSWORD --ip IP [--clean] [--clean_local_files] [--no_download] [--no_parsing] [--no_building] [--no_atlas] [--only_recent] [--no_arangodb] [--no_mitigations] [--no_validation] [--start_year START_YEAR] [--end_year END_YEAR]

Build BRON in Arango DB

options:
  -h, --help            show this help message and exit
  --username USERNAME   DB username
  --password PASSWORD   DB password
  --ip IP               DB IP address
  --clean               Clean all files and db
  --clean_local_files   Clean all local files
  --no_download         Do not download data
  --no_parsing          Do not parse data
  --no_building         Do not build BRON
  --no_atlas            Do not add ATLAS
  --only_recent         Only recent CVEs
  --no_arangodb         Do not create and import to Arangodb
  --no_mitigations      Do not create and import mitigations
  --no_validation       Do not validate entries imported to the ArangoDb
  --start_year START_YEAR
                        Start year
  --end_year END_YEAR   End year
```

## Structure of BRON
See `graph_db/schemas`

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

DTRAP paper: [https://dl.acm.org/doi/full/10.1145/3615668](https://dl.acm.org/doi/full/10.1145/3615668)
```
@article{hemberg2024enhancements,
  title={Enhancements to threat, vulnerability, and mitigation knowledge for cyber analytics, hunting, and simulations},
  author={Hemberg, Erik and Turner, Matthew J and Rutar, Nick and O’reilly, Una-May},
  journal={Digital Threats: Research and Practice},
  volume={5},
  number={1},
  pages={1--33},
  year={2024},
  publisher={ACM New York, NY}
}
```
