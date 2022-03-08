import os
import unittest
import json

import jsonschema


class TestSchema(unittest.TestCase):
    def test_bron_graph_db_tactic_schema(self):
        file_path = os.path.join("graph_db/schemas", "tactic_schema.json")
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_key": "tactic_00001",
            "original_id": "TA0009",
            "datatype": "tactic",
            "name": "collection",
            "metadata": {
                "description": "The adversary is trying to gather data of interest to their goal.\n\nCollection consists of techniques adversaries may use to gather information and the sources information is collected from that are relevant to following through on the adversary's objectives. Frequently, the next goal after collecting data is to steal (exfiltrate) the data. Common target sources include various drive types, browsers, audio, video, and email. Common collection methods include capturing screenshots and keyboard input.",
                "short_description": "The adversary is trying to gather data of interest to their goal.",
            },
        }
        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_technique_schema(self):
        file_path = os.path.join("graph_db/schemas", "technique_schema.json")
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_key": "technique_00015",
            "original_id": "T1001",
            "datatype": "technique",
            "name": "Data Obfuscation",
            "metadata": {
                "description": "Adversaries may obfuscate command and control traffic to make it more difficult to detect. Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being seen. This encompasses many methods, such as adding junk data to protocol traffic, using steganography, or impersonating legitimate protocols. ",
                "short_description": "Adversaries may obfuscate command and control traffic to make it more difficult to detect. Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being seen. This encompasses many methods, such as adding junk data to protocol traffic, using steganography, or impersonating legitimate protocols. ",
            },
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_technique_detection_schema(self):
        file_path = os.path.join("graph_db/schemas", "technique_detection_schema.json")
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_key": "technique_detection_00000",
            "original_id": "T1001",
            "name": "Data Obfuscation",
            "datatype": "technique_detection",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_technique_mitigation_schema(self):
        file_path = os.path.join("graph_db/schemas", "technique_mitigation_schema.json")
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_key": "technique_mitigation_00000",
            "original_id": "M1013",
            "name": "Application Developer Guidance",
            "datatype": "technique_mitigation",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_capec_schema(self):
        file_path = os.path.join("graph_db/schemas", "capec_schema.json")
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_key": "capec_00581",
            "original_id": "1",
            "datatype": "capec",
            "name": "Accessing Functionality Not Properly Constrained by ACLs",
            "metadata": {
                "description": "",
                "short_description": "In applications, particularly web applications, access to functionality is mitigated by an authorization framework. This framework maps Access Control Lists (ACLs) to elements of the application's functionality; particularly URL's for web apps. In the case that the administrator failed to specify an ACL for a particular element, an attacker may be able to access it with impunity. An attacker with the ability to access functionality not properly constrained by ACLs can obtain sensitive information and possibly compromise the entire application. Such an attacker can access resources that must be available only to users at a higher privilege level, can access management sections of the application, or can run queries for data that they otherwise not supposed to.",
            },
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_capec_detection_schema(self):
        file_path = os.path.join("graph_db/schemas", "capec_detection_schema.json")
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_key": "capec_detection_00016",
            "original_id": "7",
            "name": "Blind SQL Injection",
            "metadata": "The only indicators of successful Blind SQL Injection are the application or database logs that show similar queries with slightly differing logical conditions that increase in complexity over time. However, this requires extensive logging as well as knowledge of the queries that can be used to perform such injection and return meaningful information from the database.",
            "datatype": "capec_detection",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_capec_mitigation_schema(self):
        file_path = os.path.join("graph_db/schemas", "capec_mitigation_schema.json")
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_key": "capec_mitigation_00000",
            "original_id": "1",
            "name": "Accessing Functionality Not Properly Constrained by ACLs",
            "metadata": '\n               In a J2EE setting, administrators can associate a role that is impossible for the authenticator to grant users, such as "NoAccess", with all Servlets to which access is guarded by a limited number of servlets visible to, and accessible by, the user.\n               Having done so, any direct access to those protected Servlets will be prohibited by the web container.\n               In a more general setting, the administrator must mark every resource besides the ones supposed to be exposed to the user as accessible by a role impossible for the user to assume. The default security setting must be to deny access and then grant access only to those resources intended by business logic.\n            ',
            "datatype": "capec_mitigation",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_cwe_schema(self):
        file_path = os.path.join("graph_db/schemas", "cwe_schema.json")
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_key": "cwe_01127",
            "original_id": "1004",
            "datatype": "cwe",
            "name": "Sensitive Cookie Without 'HttpOnly' Flag",
            "metadata": {
                "description": "The HttpOnly flag directs compatible browsers to prevent client-side script from accessing cookies. Including the HttpOnly flag in the Set-Cookie HTTP response header helps mitigate the risk associated with Cross-Site Scripting (XSS) where an attacker's script code might attempt to read the contents of a cookie and exfiltrate information obtained. When set, browsers that support the flag will not reveal the contents of the cookie to a third party via client-side script executed via XSS.",
                "short_description": "The software uses a cookie to store sensitive information, but the cookie is not marked with the HttpOnly flag.",
            },
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

        instance = {
            "_key": "cwe_01127",
            "original_id": "1004",
            "datatype": "cwe",
            "name": "Sensitive Cookie Without 'HttpOnly' Flag",
            "metadata": {
                "description": None,
                "short_description": "The software uses a cookie to store sensitive information, but the cookie is not marked with the HttpOnly flag.",
            },
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_cwe_detection_schema(self):
        file_path = os.path.join("graph_db/schemas", "cwe_detection_schema.json")
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_key": "cwe_detection_00017",
            "original_id": "14",
            "name": "Compiler Removal of Code to Clear Buffers",
            "metadata": {
                "Method": "Black Box",
                "Description": "This specific weakness is impossible to detect using black box methods. While an analyst could examine memory to see that it has not been scrubbed, an analysis of the executable would not be successful. This is because the compiler has already removed the relevant code. Only the source code shows whether the programmer intended to clear the memory or not, so this weakness is indistinguishable from others.",
            },
            "datatype": "cwe_detection",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_cwe_mitigation_schema(self):
        file_path = os.path.join("graph_db/schemas", "cwe_mitigation_schema.json")
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_key": "cwe_mitigation_00000",
            "original_id": "5",
            "name": "J2EE Misconfiguration: Data Transmission Without Encryption",
            "metadata": {
                "Phase": "System Configuration",
                "Description": "The application configuration should ensure that SSL or an encryption mechanism of equivalent strength and vetted reputation is used for all access-controlled pages.",
            },
            "datatype": "cwe_mitigation",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_cve_schema(self):
        file_path = os.path.join("graph_db/schemas", "cve_schema.json")
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_key": "cve_02127",
            "original_id": "CVE-1999-0001",
            "datatype": "cve",
            "name": "",
            "metadata": {
                "weight": 5,
                "description": "ip_input.c in BSD-derived TCP/IP implementations allows remote attackers to cause a denial of service (crash or hang) via crafted packets.",
            },
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_cve_schema(self):
        file_path = os.path.join("graph_db/schemas", "cpe_schema.json")
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_key": "cpe_02052",
            "original_id": "cpe:2.3:o:freebsd:freebsd:2.1.6:*:*:*:*:*:*:*",
            "datatype": "cpe",
            "name": "",
            "metadata": {"product": "freebsd", "vendor": "freebsd", "version": "2.1.6"},
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_d3fend_mitigation_schema(self):
        file_path = os.path.join("graph_db/schemas", "d3fend_mitigation_schema.json")
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_key": "d3fend_mitigation_00000",
            "name": "Active Certificate Analysis",
            "metadata": {"d3fend-id": "D3-ACA"},
            "original_id": "ActiveCertificateAnalysis",
            "datatype": "d3fend_mitigation",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_engage_activity_schema(self):
        file_path = os.path.join("graph_db/schemas", "engage_activity_schema.json")
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_key": "engage_activity_00000",
            "original_id": "EAC0001",
            "name": "API Monitoring",
            "datatype": "engage_activity",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_engage_approach_schema(self):
        file_path = os.path.join("graph_db/schemas", "engage_approach_schema.json")
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_key": "engage_approach_00000",
            "original_id": "EAP0001",
            "name": "Collection",
            "datatype": "engage_approach",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_engage_goal_schema(self):
        file_path = os.path.join("graph_db/schemas", "engage_goal_schema.json")
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_key": "engage_goal_00000",
            "original_id": "EGO0001",
            "name": "Expose",
            "datatype": "engage_goal",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_CapecCapec_detection_schema(self):
        file_path = os.path.join(
            "graph_db/schemas/edge_collections", "CapecCapec_detection_schema.json"
        )
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_from": "capec/capec_00587",
            "_to": "capec_detection/capec_detection_00016",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_CapecCapec_mitigation_schema(self):
        file_path = os.path.join(
            "graph_db/schemas/edge_collections", "CapecCapec_mitigation_schema.json"
        )
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_from": "capec/capec_00581",
            "_to": "capec_mitigation/capec_mitigation_00000",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_CweCwe_detection_schema(self):
        file_path = os.path.join(
            "graph_db/schemas/edge_collections", "CweCwe_detection_schema.json"
        )
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_from": "cwe/cwe_00587",
            "_to": "cwe_detection/cwe_detection_00016",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_CweCwe_mitigation_schema(self):
        file_path = os.path.join(
            "graph_db/schemas/edge_collections", "CweCwe_mitigation_schema.json"
        )
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_from": "cwe/cwe_00581",
            "_to": "cwe_mitigation/cwe_mitigation_00000",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_CapecCwe_schema(self):
        file_path = os.path.join(
            "graph_db/schemas/edge_collections", "CapecCwe_schema.json"
        )
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {"_from": "capec/capec_00581", "_to": "cwe/cwe_00000"}

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_CveCpe_schema(self):
        file_path = os.path.join(
            "graph_db/schemas/edge_collections", "CveCpe_schema.json"
        )
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {"_from": "cve/cve_00581", "_to": "cpe/cpe_00000"}

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_CweCve_schema(self):
        file_path = os.path.join(
            "graph_db/schemas/edge_collections", "CweCve_schema.json"
        )
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {"_from": "cwe/cwe_00581", "_to": "cve/cve_00000"}

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_D3fend_mitigationTechnique_schema(self):
        file_path = os.path.join(
            "graph_db/schemas/edge_collections",
            "D3fend_mitigationTechnique_schema.json",
        )
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_to": "d3fend_mitigation/d3fend_mitigation_00581",
            "_from": "technique/technique_00000",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_Engage_approachEngage_activity_schema(self):
        file_path = os.path.join(
            "graph_db/schemas/edge_collections",
            "Engage_approachEngage_activity_schema.json",
        )
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_from": "engage_approach/engage_approach_00581",
            "_to": "engage_activity/engage_activity_00000",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_Engage_goalEngage_approach_schema(self):
        file_path = os.path.join(
            "graph_db/schemas/edge_collections",
            "Engage_goalEngage_approach_schema.json",
        )
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_to": "engage_approach/engage_approach_00581",
            "_from": "engage_goal/engage_goal_00000",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_TacticTechnique_schema(self):
        file_path = os.path.join(
            "graph_db/schemas/edge_collections", "TacticTechnique_schema.json"
        )
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {"_to": "technique/technique_00581", "_from": "tactic/tactic_00000"}

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_TechniqueCapec_schema(self):
        file_path = os.path.join(
            "graph_db/schemas/edge_collections", "TechniqueCapec_schema.json"
        )
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {"_from": "technique/technique_00581", "_to": "capec/capec_00000"}

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_TechniqueTechnique_detection_schema(self):
        file_path = os.path.join(
            "graph_db/schemas/edge_collections",
            "TechniqueTechnique_detection_schema.json",
        )
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_from": "technique/technique_00581",
            "_to": "technique_detection/technique_detection_00000",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_TechniqueTechnique_mitigation_schema(self):
        file_path = os.path.join(
            "graph_db/schemas/edge_collections",
            "TechniqueTechnique_mitigation_schema.json",
        )
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_from": "technique/technique_00581",
            "_to": "technique_mitigation/technique_mitigation_00000",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)

    def test_bron_graph_db_TechniqueEngage_activity_schema(self):
        file_path = os.path.join(
            "graph_db/schemas/edge_collections", "TechniqueEngage_activity_schema.json"
        )
        with open(file_path, "r") as fd:
            schema = json.load(fd)

        instance = {
            "_from": "technique/technique_00581",
            "_to": "engage_activity/engage_activity_00000",
        }

        # TODO assert that exception is not thrown
        jsonschema.validate(instance=instance, schema=schema)
        self.assertTrue(True)
