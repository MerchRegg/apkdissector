from unittest import TestCase
from dissector.plugins.build_graph_plugin import BuildGraphPlugin

class TestBuildGraphPlugin(TestCase):
    """
    def test_analyze(self):
        wrong_dir = "/home/marco/APKs/tcpchat/wrong_dir.txt"
        right_dir = "/home/marco/APKs/tcpchat/app-debug.apk"
        complete_dir = "/home/marco/APKs/tcpchat/app-debug_graph_complete.gexf"
        #THIS SHOULD BE THE GRAPH PREVIOULSY BUILT WITH ANDROGEXF
        expected_graph = open("/home/marco/APKs/tcpchat/app-debug_graph.gexf", "r").read()

        buildgraph = BuildGraphPlugin(wrong_dir)
        with self.assertRaises(ValueError):
            buildgraph.analyze()

        buildgraph = BuildGraphPlugin(right_dir)
        buildgraph.analyze()
        buildgraph.save_analysis_to_file(complete_dir)
        self.assertEqual(expected_graph, buildgraph.analysis)
    """

    """
    def test_trim(self):
        right_dir = "/home/marco/APKs/tcpchat/app-debug.apk"
        trimmed_dir = "/home/marco/APKs/tcpchat/app-debug_graph_trimmed.gexf"

        buildgraph = BuildGraphPlugin(right_dir)
        buildgraph.analyze()
        buildgraph.trim_graph("support")
        buildgraph.trimmed_analysis_to_file(trimmed_dir)

    """
    def test_sub(self):
        right_dir = "/home/marco/APKs/tcpchat/app-debug.apk"
        subbed_dir = "/home/marco/APKs/tcpchat/app-debug_graph_subbed.gexf"

        buildgraph = BuildGraphPlugin(right_dir)
        buildgraph.analyze()
        buildgraph.class_sub_graph("support")
        buildgraph.subbed_analysis_to_file(subbed_dir)
