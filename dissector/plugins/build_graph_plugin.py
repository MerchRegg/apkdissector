# from dissector.plugins.libs.androguard.core import androconf
# from dissector.plugins.libs.androguard.core.analysis import analysis
# from dissector.plugins.libs.androguard.core.analysis import ganalysis
# from dissector.plugins.libs.androguard.core.bytecodes import apk
# from dissector.plugins.libs.androguard.core.bytecodes import dvm
import re
from dissector.plugins.libs.androguard.core import androconf
from dissector.plugins.libs.androguard.core.analysis import analysis
from dissector.plugins.libs.androguard.core.analysis import ganalysis
from dissector.plugins.libs.androguard.core.bytecodes import apk
from dissector.plugins.libs.androguard.core.bytecodes import dvm

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
        self.class_subbed_analysis = None

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

    def subbed_analysis_to_file(self, path):
        """
        Saves the subgraph analysis done to the specified path
        :param path: the path to which save the analysis
        """
        if self.class_subbed_analysis is not None:
            androconf.save_to_disk(self.class_subbed_analysis, path)
        else:
            raise ValueError("There is no graph to be saved!")

    def analyze(self, classes_of_interest = []):
        """
        Analyzes an apk or dex file specified and saves it.
        """
        ret_type = androconf.is_android(self.target)
        #androconf.set_debug()
        vm = None
        vms = []
        dexes = []
        a = None
        if ret_type == "APK":
            a = apk.APK(self.target)
            if a.is_valid_APK():
                #dexes.append(a.get_all_dex())
                print "getting dexes.."
                dexes = [d for d in a.get_all_dex()]
                print "dexes got!"
                #vm = dvm.DalvikVMFormat(dexes[1])
                for d in dexes:
                    vms.append(dvm.DalvikVMFormat(d))
                    print "dvm appended"
                #vm = dvm.DalvikVMFormat(a.get_dex())
                #         for d in a.get_all_dex():
                #            print "adding vm.."
                #            vms.append(dvm.DalvikVMFormat(d))
                #            print "vm added.."
                #vm = dvm.DalvikVMFormat(a.get_all_dex())
            else:
                print "INVALID APK"
        elif ret_type == "DEX":
            try:
                #vms = [dvm.DalvikVMFormat(open(self.target, "rb").read())]
                vm = dvm.DalvikVMFormat(open(self.target, "rb").read())
            except Exception, e:
                print "INVALID DEX", e
        else:
            raise ValueError("Invalid target to analyze!")
        print "added all vms, analyzing.."

        print "creating multidex DalvikVMFormat"
        multidex_vm = dvm.DalvikVMFormat(vms)
        multidex_vm.set_classes_of_intetest(classes_of_interest)
        print "multidex DalvikVMFormat created!"
        vmx = analysis.VMAnalysis(multidex_vm)
        print "analyzed vms, creating graph.."
        self.gvmx = ganalysis.GVMAnalysis(vmx, a)
        print "graph created, saving to gexf.."
        self.analysis = self.gvmx.export_to_gexf()
        print("Done.")

        #log  =  open("log.log" , "wr")
        #for i in vm.get_all_fields():
            #print i.show()
        """
        for i in vm.get_methods():
            log.write("_____________________START_______________________\n")
            log.write(i.get_name() + "|||" + i.get_class_name() + "|||"+i.get_descriptor()+"\n")
            log.write("______________________END________________________\n")

        vm = vmx.get_vm()
        for j in vmx.get_tainted_packages().get_internal_packages() :
            print "_____________________START_______________________"
            print j.get_src(vm.get_class_manager() )
            print j.get_dst(vm.get_class_manager() )
            print "______________________END________________________"
        """
        # for c in vm.get_classes():
        #     print "_____________________START_______________________"
        #     print c.show()
        #     print "_____________________END_______________________"

    def trim_graph(self, trim_regex):
        """
        Updates the graph of the analysis done trimming it from the nodes with label matching the given regex
        :param trim_regex: the regex to match with every node label
        """
        print("Trimming graph")
        if self.gvmx is None:
            raise ValueError("There is no graph to be trimmed!")
        trimmed = ganalysis.Graph()
        pat = re.compile(trim_regex)

        for edge in self.gvmx.G.edges():
            label = self.gvmx.nodes_id[edge[0]].label + self.gvmx.nodes_id[edge[1]].label
            if pat.search(label) is None:
                trimmed.add_edge(edge[0],edge[1])
        self.gvmx.G = trimmed
        self.trimmed_analysis = self.gvmx.export_to_gexf()

        """
        temp = self.gvmx.G
        self.gvmx.G = trimmed
        self.trimmed_analysis = self.gvmx.export_to_gexf()
        self.gvmx.G = temp
        """

    def bf_graph(self, original_graph, nodes, visited, start):
        # print("getting subgraph of " + self.gvmx.nodes_id[start].label)
        queue = [start]
        while queue:
            current = queue.pop()
            if current not in visited:
                #print("Analyzing " + self.gvmx.nodes_id[current].label)
                neighbors = original_graph.neighbors(current)
                for neighbor in neighbors:
                    #print("Found neighbor " + self.gvmx.nodes_id[neighbor].label)
                    if neighbor not in visited:
                        visited[neighbor] = True
                        #print("Adding edge " + self.gvmx.nodes_id[current].label + "->" + self.gvmx.nodes_id[neighbor].label)
                        nodes.append(current)
                        nodes.append(neighbor)
                        #nodes.append(self.gvmx.nodes_id[neighbor])
                        queue.append(neighbor)
                    #else:
                        #print("Already visited")
                visited[current] = True

    def sub(self, class_names):
        """
        Gets a subset of the analyzed graph made of paths from the nodes of the methods in the classes with
        given class_name
        :param class_names: the array of names of the classes of interest
        """
        print("Subsetting graph")
        if self.gvmx is None:
            raise ValueError("There is no graph to be subbed!")

        nodes = []
        visited = {}
        pat = []

        while class_names:
            class_name = class_names.pop()
            print "subsetting for: " + class_name
            pat.append(re.compile(class_name))

        for node in self.gvmx.G.nodes():
            found = False
            if node not in visited:
                current = self.gvmx.nodes_id[node]
                label =  current.label
                #make it more efficient
                for pattern in pat:
                    if pattern.search(label) is not None:
                        found = True
                if found:
                    self.bf_graph(self.gvmx.G, nodes, visited, node)

        self.gvmx.G = self.gvmx.G.subgraph(nodes)
        self.class_subbed_analysis = self.gvmx.export_to_gexf()
        """
        temp = self.gvmx.G
        self.gvmx.G = self.gvmx.G.subgraph(nodes)
        self.class_subbed_analysis = self.gvmx.export_to_gexf()
        #print(self.class_subbed_analysis)
        self.gvmx.G = temp
        """

    def trim_sub_save(self, class_names, trim_regex, path):
        temp = self.gvmx.G
        self.trim_graph(trim_regex)
        self.sub(class_names)
        #print "post sub"
        self.gvmx.G = temp
        if self.class_subbed_analysis is not None:
            androconf.save_to_disk(self.class_subbed_analysis, path)
        else:
            raise ValueError("There is no graph to be saved!")

    def analyze_trim(self, trim_regex):
        temp = self.gvmx.G
        ret = self.trim_graph(trim_regex)
        self.gvmx.G = temp
        return ret

    def analyze_sub(self, class_names):
        temp = self.gvmx.G
        ret = self.sub(class_names)
        self.gvmx.G = temp
        return ret








