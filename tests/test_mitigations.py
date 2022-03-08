import os
import unittest

import arango
import dotenv

from graph_db.bron_arango import get_edge_collection_name


class TestMitigations(unittest.TestCase):
    def check_orphans(self, db, mitigation_collection_name, basename):
        edge_name = get_edge_collection_name(basename, mitigation_collection_name)
        print(f"CHECK ORPHANS in {basename} {mitigation_collection_name} {edge_name}")
        _mitigation_ids = set()
        _mitigations = db.collection(mitigation_collection_name).all()
        for _mitigation_id in _mitigations:
            _mitigation_ids.add(_mitigation_id["_id"])

        _mitigation_edges = set()
        edge_mitgation = db.collection(edge_name).all()
        for i, entry in enumerate(edge_mitgation):
            _mitigation_edges.add(entry["_to"])

        self.assertTrue(
            len(_mitigation_ids - _mitigation_edges) == 0,
            f"{basename} {mitigation_collection_name} {len(_mitigation_ids)} != {len(_mitigation_edges)};",
        )
        print(
            f"{basename} {mitigation_collection_name} {len(_mitigation_ids)} == {len(_mitigation_edges)}"
        )

    def test_orphans(self):
        dotenv.find_dotenv(raise_error_if_not_found=True)
        dotenv.load_dotenv()
        password = str(os.environ.get("BRON_PWD"))
        username = "root"
        ip = str(os.environ.get("BRON_SERVER_IP"))
        client = arango.ArangoClient(hosts=f"http://{ip}:8529")
        db = client.db(
            "BRON", username=username, password=password, auth_method="basic"
        )
        mitigation_collections = ("cwe", "capec", "technique")
        variants = ("mitigation", "detection")
        for mitigation_collection in mitigation_collections:
            for variant in variants:
                if mitigation_collection == "technique" and variant == "mitigation":
                    pass
                mitigation_collection_name = f"{mitigation_collection}_{variant}"
                self.check_orphans(
                    db, mitigation_collection_name, mitigation_collection
                )

        client.close()


class TestCWEMitigations(unittest.TestCase):
    def test_orphans(self):
        dotenv.find_dotenv(raise_error_if_not_found=True)
        dotenv.load_dotenv()
        password = str(os.environ.get("BRON_PWD"))
        username = "root"
        ip = str(os.environ.get("BRON_SERVER_IP"))
        client = arango.ArangoClient(hosts=f"http://{ip}:8529")
        db = client.db(
            "BRON", username=username, password=password, auth_method="basic"
        )
        cwe_mitigation_ids = set()
        cwe_mitigations = db.collection("cwe_mitigation").all()
        for cwe_mitigation_id in cwe_mitigations:
            cwe_mitigation_ids.add(cwe_mitigation_id["_id"])

        cwe_mitigation_edges = set()
        CweCwe_mitgation = db.collection("CweCwe_mitigation").all()
        for cwe_cwe_mitigation in CweCwe_mitgation:
            cwe_mitigation_edges.add(cwe_cwe_mitigation["_to"])

        client.close()
        self.assertTrue(
            len(cwe_mitigation_ids - cwe_mitigation_edges) == 0,
            f"{len(cwe_mitigation_ids)} != {len(cwe_mitigation_edges)}",
        )
        print(f"{len(cwe_mitigation_ids)} == {len(cwe_mitigation_edges)}")
