import unittest

from mitre_nist_data.download_threat_data import main


class TestDownloadThreatData(unittest.TestCase):

    def test_main(self):
        main()
        # TODO meaningful assert...
        self.assertEquals(True, True)
