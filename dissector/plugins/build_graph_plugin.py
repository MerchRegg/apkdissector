from androguard.core import androconf
from androguard.core.analysis import analysis
from androguard.core.analysis import ganalysis
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
import re

from dissector.plugins.generic_plugin import DissectorPlugin


class BuildGraphPlugin(DissectorPlugin):
    """This plugin emulates the androgexf plugin of androguard
    to build a method calls graph given an apk or dex file.
    """

    def __init__(self, target):
        """
        Creates a new instance of the plugin to analyze call graph.
        """
        super(BuildGraphPlugin, self).__init__(target)
        self.gvmx = None
        self.trimmed_analysis = None

    def save_analysis_to_file(self, path):
        """
        Saves the analysis done to the specified path
        :param path: the path to which save the analysis
        """
        if self.analysis is not None:
            androconf.save_to_disk(self.analysis, path)
        else:
            raise ValueError("There is no analysis to be saved!")

    def trimmed_analysis_to_file(self, path):
        """
        Saves the trimmed analysis done to the specified path
        :param path: the path to which save the analysis
        """
        if self.trimmed_analysis is not None:
            #print("SAVING TRIMMED")
            #print(self.trimmed_analysis)
            androconf.save_to_disk(self.trimmed_analysis, path)
        else:
            raise ValueError("There is no graph to be saved!")

    def analyze(self):
        """
        Analyzes an apk or dex file specified and saves it.
        """
        ret_type = androconf.is_android(self.target)
        vm = None
        a = None
        if ret_type == "APK":
            a = apk.APK(self.target)
            if a.is_valid_APK():
                vm = dvm.DalvikVMFormat(a.get_dex())
            else:
                print "INVALID APK"
        elif ret_type == "DEX":
            try:
                vm = dvm.DalvikVMFormat(open(self.target, "rb").read())
            except Exception, e:
                print "INVALID DEX", e
        else:
            raise ValueError("Invalid target to analyze!")

        vmx = analysis.VMAnalysis(vm)
        self.gvmx = ganalysis.GVMAnalysis(vmx, a)

        self.analysis = self.gvmx.export_to_gexf()
        print("Analyzed")


    def trim_graph(self, trim_regex):
        """
        Updates the graph of the analysis done trimming it from the nodes with label matching the given regex
        :param trim_regex: the regex to match with every node label
        """
        print("Trimming graph")
        if(self.gvmx is None):
            raise ValueError("There is no graph to be trimmed!")
        pat = re.compile(trim_regex)
        for node in self.gvmx.G.nodes():
            label = self.gvmx.nodes_id[node].label
            #print("Analyzing node with label: %s", label)
            if pat.search(label):
                #print("Removing node with label: %s", label)
                before = self.gvmx.G.number_of_nodes()
                self.gvmx.G.remove_node(node)
                after = self.gvmx.G.number_of_nodes()
                #print("Nodes before:%s after:%s", before, after)
        self.trimmed_analysis = self.gvmx.export_to_gexf()
        #print(self.trimmed_analysis)


