import argparse
import sys

import re
import requests
from typing import Dict, Set, List, Any

from pdfminer.high_level import extract_text
from bs4 import BeautifulSoup

from graph_db.query_graph_db import get_connection_counts, get_graph_traversal
from BRON.build_BRON import id_dict_paths


REPORT_URL = 'https://media.defense.gov/2020/Dec/17/2002554125/-1/-1/0/AUTHENTICATION_MECHANISMS_CSA_U_OO_198854_20.PDF'
MDR_URL = 'https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/'
# TODO get 403 for MDR_HTML so it is amnually downloaded...
MDR_HTM = 'graph_db/example_data/mdr_solarigate.htm'
FIRE_EYE_URL = 'https://github.com/fireeye/red_team_tool_countermeasures/blob/master/CVEs_red_team_tools.md'
# TODO all in one regex
ta_re_pattern = "TA00\d{2}"
ta_prog = re.compile(ta_re_pattern)
t_re_pattern = "(T\d{4}(\.\d{3})?)"
t_prog = re.compile(t_re_pattern)
cve_re_pattern = "CVE-\d{4}-\d{4,7}"
cve_prog = re.compile(cve_re_pattern)

def get_report(url: str) -> Dict[str, Set[str]]:
    response = requests.get(url, timeout=5)
    # TODO use tmpfile module
    tmp_file_path = '/tmp/metadata.pdf'
    result = {}
    text = ""
    if 'pdf' in response.headers['Content-Type']:
         with open(tmp_file_path, 'wb') as f:
             f.write(response.content)
             text = extract_text(tmp_file_path)
             # Parse data types from report
             # TODO pares more info?
    elif response.status_code == 403:
        # TODO hack. Manually downloaded webpge
        with open(MDR_HTM, 'r') as fd:
            soup = BeautifulSoup(fd.read(), 'lxml')
            text = soup.get_text()        
    else:
        html_text = response.text
        soup = BeautifulSoup(html_text, 'html.parser')
        text = soup.get_text()        

    result['tactic'] = set(ta_prog.findall(text))
    result['technique'] = set([_[0] for _ in t_prog.findall(text)])
    result['cve'] = set(cve_prog.findall(text)) 
    
    return result

# Query bron with info
def get_queries(all_starting_points: Dict[str, List[str]], ip: str, password: str, username: str) -> Dict[str, Any]:
    results = {}
    for datatype, starting_points in all_starting_points.items():
        assert datatype in id_dict_paths
        print(datatype)
        records = get_connection_counts(starting_points, datatype, username, ip, password)
        results['records'] = records
        print(records)
        traversals = get_graph_traversal(starting_points, datatype, username, ip, password)
        print(len(traversals))
        results['traversals'] = traversals

    return results
# Make "network"

# Query bron with network for report


# TODO

# - BRON edges

# - Public temp on aws

# - Docker file

# - Get the other attack data and link: intrusion set(groups), realtions, malware, coa, tool

# - BRON display names and metadata

def main(ip: str, password: str, username: str, url: str) -> Dict[str, Any]:
    data = get_report(url)
    data = dict((k, list(v)) for k, v in data.items())
    results = get_queries(data, ip, password, username)
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='BRON Arango Example')
    parser.add_argument("--username", type=str, required=True,
                        help="DB username")
    parser.add_argument("--password", type=str, required=True,
                        help="DB password")
    parser.add_argument("--ip", type=str, required=True,
                        help="DB IP address")
    parser.add_argument("--url", type=str, default='',
                        help="URL to parse and pass through BRON")
    args = parser.parse_args(sys.argv[1:])
    _ = main(args.ip, args.password, args.username, args.url)
