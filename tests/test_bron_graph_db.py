import unittest
import json
import os

import arango
import dotenv


class TestBRONGraphDB(unittest.TestCase):
    def test_collections(self):
        with open("graph_db/schema.json", "r") as fd:
            schema = json.load(fd)

        dotenv.load_dotenv()
        password = str(os.environ.get("BRON_PWD"))
        username = "root"
        ip = str(os.environ.get("BRON_SERVER_IP"))
        client = arango.ArangoClient(hosts=f"http://{ip}:8529")
        db = client.db("BRON", username=username, password=password, auth_method="basic")
        db_collections = db.collections()
        client.close()
        expected_collections = set()
        for value in schema.values():
            for element in value.keys():
                expected_collections.add(element)

        expected_collections = set(expected_collections)
        db_collections = set([_["name"] for _ in db_collections if not _["name"].startswith("_")])
        self.assertTrue(
            len(db_collections - expected_collections) == 0,
            f"{db_collections} != {expected_collections}\nDiff:\n {db_collections - expected_collections}",
        )


class TestTechniques(unittest.TestCase):
    def test_technique_tactic_orphans(self):
        dotenv.load_dotenv()
        password = str(os.environ.get("BRON_PWD"))
        username = "root"
        ip = str(os.environ.get("BRON_SERVER_IP"))
        client = arango.ArangoClient(hosts=f"http://{ip}:8529")
        db = client.db("BRON", username=username, password=password, auth_method="basic")
        technique_ids = set()
        technique_documents = db.collection("technique").all()
        for technique_id in technique_documents:
            technique_ids.add(technique_id["_id"])

        technique_edges = set()
        tactic_technique_documents = db.collection("TacticTechnique").all()
        for tactic_technique_edge in tactic_technique_documents:
            technique_edges.add(tactic_technique_edge["_to"])

        client.close()
        print(technique_ids - technique_edges)
        self.assertTrue(
            len(technique_ids - technique_edges) == 0,
            f"{len(technique_ids)} != {len(technique_edges)}",
        )
        print(f"{len(technique_ids)} == {len(technique_edges)}")
