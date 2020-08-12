import os
import unittest

from meta_analysis.draw_BRON import draw_bron


class TestVisualization(unittest.TestCase):
    def test_draw_bron(self):
        bron_data_path = "tests/test_BRON.json"
        graph_name = "test"
        save_file_path = "bron_plot_test.pdf"
        try:
            os.remove(save_file_path)
        except FileNotFoundError:
            pass
        draw_bron(bron_data_path, graph_name)
        self.assertTrue(os.path.exists(save_file_path))


if __name__ == "__main__":
    unittest.main()
