from unittest import TestCase
from dissector.plugins.build_graph_plugin import BuildGraphPlugin

class TestBuildGraphPlugin(TestCase):
    """
        wrong_dir = "/home/marco/apks/tcpchat/wrong_dir.txt"
        right_dir = "/home/marco/apks/tcpchat/app-debug.apk"
        complete_dir = "/home/marco/apks/tcpchat/app-debug_graph_complete.gexf"
    """

    """
    def test_analyze(self):
        wrong_dir = "/home/marco/apks/testapp/wrong_dir.txt"
        right_dir = "/home/marco/apks/testapp/vulnerable.apk"
        complete_dir = "/home/marco/apks/testapp/vulnerable_graph_complete.gexf"
        #THIS SHOULD BE THE GRAPH PREVIOULSY BUILT WITH ANDROGEXF
        #expected_graph = open("/home/marco/apks/tcpchat/app-debug_graph.gexf", "r").read()

        buildgraph = BuildGraphPlugin(wrong_dir)
        #with self.assertRaises(ValueError):
            #buildgraph.analyze()

        buildgraph = BuildGraphPlugin(right_dir)
        buildgraph.analyze()
        buildgraph.save_analysis_to_file(complete_dir)
        #self.assertEqual(expected_graph, buildgraph.analysis)
"""

    """
        right_dir = "/home/marco/apks/tcpchat/app-debug.apk"
        trimmed_dir = "/home/marco/apks/tcpchat/app-debug_graph_trimmed.gexf"
    """
    """

    #Questo test taglia i nodi delle classi specificate e crea il sottografo delle classi specificate
    def test_trim_sub(self):
        right_dir = "/home/marco/apks/testapp/vulnerable.apk"
        subbed_dir = "/home/marco/apks/testapp/trimmed_subbed2.gexf"
        choosen_classes = ["org/sid/vulnerableappjni/MediaActivity"]
        class_to_trim = "android/support"

        buildgraph = BuildGraphPlugin(right_dir)
        #buildgraph.analyze(["Landroid/content/Intent;"])
        buildgraph.analyze()
        buildgraph.trim_sub_save(choosen_classes, class_to_trim, subbed_dir)


    #Questo test crea il sottografo delle classi specificate
    def test_sub(self):
        right_dir = "/home/marco/apks/testapp/vulnerable.apk"
        subbed_dir = "/home/marco/apks/testapp/vulnerable_graph_subbed.gexf"

        buildgraph = BuildGraphPlugin(right_dir)
        buildgraph.analyze()
        buildgraph.class_sub_graph("org.sid.vulnerableappjni.MediaActivity")
        buildgraph.subbed_analysis_to_file(subbed_dir)
    """

    # Questo test taglia i nodi delle classi specificate e crea il grafo rimanente
    def test_trim(self):
        #right_dir = "/home/marco/apks/testapp/vulnerable.apk"
        right_dir = "/home/marco/apks/facebook/com.facebook.katana_v89.0.0.17.70.apk"
        #right_dir = "/home/marco/apks/twitter/com.twitter.android_caac238c.apk"
        #trimmed_dir = "/home/marco/apks/testapp/vulnerable_graph_trimmed.gexf"
        trimmed_dir = "/home/marco/apks/facebook/trimmed_facebook.gexf"
        #trimmed_dir = "/home/marco/apks/twitter/trimmed_twitter.gexf"
        buildgraph = BuildGraphPlugin(right_dir)
        buildgraph.analyze()
        buildgraph.trim_graph("support")
        buildgraph.trimmed_analysis_to_file(trimmed_dir)
