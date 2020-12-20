import argparse
import sys
import re
import requests
from typing import Dict, Set, List

from pdfminer.high_level import extract_text

from graph_db.query_graph_db import get_connection_counts
from BRON.build_BRON import id_dict_paths


REPORT_URL = 'https://media.defense.gov/2020/Dec/17/2002554125/-1/-1/0/AUTHENTICATION_MECHANISMS_CSA_U_OO_198854_20.PDF'
# TODO all in one regex
ta_re_pattern = "TA00\d{2}"
ta_prog = re.compile(ta_re_pattern)
t_re_pattern = "(T\d{4}(\.\d{3})?)"
t_prog = re.compile(t_re_pattern)

def get_report(url: str) -> Dict[str, Set[str]]:
    response = requests.get(url, timeout=5)
    # TODO use tmpfile module
    tmp_file_path = '/tmp/metadata.pdf'
    result = {}
    if 'pdf' in response.headers['Content-Type']:
         with open(tmp_file_path, 'wb') as f:
             f.write(response.content)
             text = extract_text(tmp_file_path)
             # Parse data types from report
             # TODO pares more info?
             result['tactic'] = set(ta_prog.findall(text))
             result['technique'] = set([_[0] for _ in t_prog.findall(text)])
             
    return result

# Query bron with info
def get_queries(all_starting_points: Dict[str, List[str]], ip: str, password: str, username: str) -> None:
    for datatype, starting_points in all_starting_points.items():
        assert datatype in id_dict_paths
        print(datatype)
        records = get_connection_counts(starting_points, datatype, username, ip, password)
        print(records)
        
# Make "network"

# Query bron with network for report


# TODO

# - BRON edges

# - Public temp on aws

# - Docker file

# - Get the other attack data and link: intrusion set(groups), realtions, malware, coa, tool

# - BRON display names and metadata

def main(ip: str, password: str, username: str) -> None:
    data = get_report(REPORT_URL)
    data = dict((k, list(v)) for k, v in data.items())
    get_queries(data, ip, password, username)
    
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='BRON Arango Example')
    parser.add_argument("--username", type=str, required=True,
                        help="DB username")
    parser.add_argument("--password", type=str, required=True,
                        help="DB password")
    parser.add_argument("--ip", type=str, required=True,
                        help="DB IP address")
    args = parser.parse_args(sys.argv[1:])
    main(args.ip, args.password, args.username)
