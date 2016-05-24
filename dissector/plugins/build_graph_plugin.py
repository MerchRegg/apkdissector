from androguard.core import androconf
from androguard.core.analysis import analysis
from androguard.core.analysis import ganalysis
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm

from dissector.plugins.generic_plugin import DissectorPlugin

class BuildGraphPlugin(DissectorPlugin):

    """This plugin emulates the androgexf plugin of androguard
    to build a method calls graph given an apk or dex file.
    """

    def save_analysis_to_file(self, path):
        """
        Saves the analysis done to the specified path
        :param path: the path to which save the analysis
        """
        if self.analysis is not None:
            androconf.save_to_disk(self.analysis, path)
        else:
            raise ValueError("There is no analysis to be saved!")

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
        gvmx = ganalysis.GVMAnalysis(vmx, a)

        self.analysis = gvmx.export_to_gexf()
