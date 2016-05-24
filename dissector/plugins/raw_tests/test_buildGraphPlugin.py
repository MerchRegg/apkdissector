from unittest import TestCase
from dissector.plugins.build_graph_plugin import BuildGraphPlugin

class TestBuildGraphPlugin(TestCase):

    def test_analyze(self):
        wrong_dir = "/home/marco/APKs/tcpchat/wrong_dir.txt"
        right_dir = "/home/marco/APKs/tcpchat/app-debug.apk"
        #THIS SHOULD BE THE GRAPH PREVIOULSY BUILT WITH ANDROGEXF
        expected_graph = open("/home/marco/APKs/tcpchat/app-debug_graph.gexf", "r").read()

        buildgraph = BuildGraphPlugin(wrong_dir)
        with self.assertRaises(ValueError):
            buildgraph.analyze()

        buildgraph = BuildGraphPlugin(right_dir)
        buildgraph.analyze()
        self.assertEqual(expected_graph, buildgraph.analysis)

