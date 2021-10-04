#!/usr/bin/env python3
import sys, os, json, logging, argparse
from download_threat_information.download_threat_data import _download_attack, _download_capec, _download_cwe, _download_cve, main
from download_threat_information.parsing_scripts.parse_attack_tactic_technique import link_tactic_techniques
from download_threat_information.parsing_scripts.parse_cve import parse_cve_file
from download_threat_information.parsing_scripts.parse_capec_cwe import parse_capec_cwe_files
from utils.tutorial_util import print_files_in_folder
from BRON.build_BRON import build_graph, BRON_PATH
from path_search.path_search_BRON import main_attack
from meta_analysis.make_data_summary import load_graph_network, main_data_summary
from utils.bron_network_utils import load_graph_nodes
from meta_analysis.meta_analysis_scripts.vendor_tactic_and_cvss import bron_id_to_cpe_id, cve_to_risk, make_heat_map

def build(out_dir):
    """downloads datasets and builds the BRON graph"""
    logging.info('Downloading threat data')
    out_path = out_dir + '/download_threat_information'
    cve_years = ['2002', '2003', '2004', '2005', '2006', '2007', '2008', '2009', '2010', '2011',
                 '2012', '2013', '2014', '2015', '2016', '2017', '2018', '2019', '2020']
    main(cve_years, out_path)
    print_files_in_folder(out_path)

    logging.info('Parsing ATT&CK data')
    filename = os.path.join(out_path, 'raw_enterprise_attack.json')
    link_tactic_techniques(filename, out_path)
    print_files_in_folder(out_path)

    logging.info('Parsing CVE data')
    cve_path = os.path.join(out_path, 'raw_CVE.json.gz')
    only_recent_cves = False
    if only_recent_cves:
        save_path_file = "cve_map_cpe_cwe_score_2015_2020.json"
    else:
        save_path_file = "cve_map_cpe_cwe_score.json"
    save_file = os.path.join(out_path, save_path_file)
    parse_cve_file(cve_path, save_file)
    print_files_in_folder(out_path)

    logging.info('Parsing CAPEC data')
    capec_file = os.path.join(out_path, 'raw_CAPEC.json')
    cwe_file = os.path.join(out_path, 'raw_CWE.zip')
    parse_capec_cwe_files(capec_file, cwe_file, save_path=out_path)
    print_files_in_folder(out_path)

    # Path to save BRON output
    save_path = out_dir + '/full_data/full_output_data'
    os.makedirs(save_path, exist_ok=True)

    # Path to the downloaded threat information
    input_data_folder = out_dir + '/download_threat_information'
    BRON_original_id_to_bron_id_path = os.path.join(save_path, BRON_PATH)
    os.makedirs(BRON_original_id_to_bron_id_path, exist_ok=True)

    logging.info('Building BRON graph')
    build_graph(save_path, input_data_folder)
    print_files_in_folder(BRON_original_id_to_bron_id_path)

if __name__ == '__main__':

    # set command line args
    parser = argparse.ArgumentParser(
        description='build.py: a builder for BRON.'
    )
    parser.add_argument('-o', '--output', help='output dir', default='/tmp')

    # parse args and configuration
    args = parser.parse_args()

    # setup logging
    logging.basicConfig(level=logging.INFO, format='%(message)s')

    # run builder
    try:
        build(args.output)
    except (KeyboardInterrupt, SystemExit):
        pass
    except:
        logging.exception('Error while executing the builder.')
    else:
        sys.exit(0)

