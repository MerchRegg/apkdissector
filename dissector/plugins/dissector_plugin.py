from abc import ABCMeta, abstractmethod


class DissectorPlugin:

    __metaclass__ = ABCMeta

    """This is an abstract class to implement creating a new plugin
        Attributes:
         :param _what the object to analyze
         :type _what dictates which plugin to run when analyzing
    """

    def __init__(self, what, path="", flag=False):
        """
        Creates a new instance of a dissector plugin
        :param what: the object to be analyzed
        :param path: the path to the file to save the analysis result
        :param flag: if true the analysis is saved to file, otherwise is not
        """
        self.what = what
        self.path = path
        self.flag = flag

    @abstractmethod
    def analyze(self):
        """
        This method should analyze the what object and return a result object
        :return: the result object
        """
        pass

    def getWhat(self):
        """Get the object to be analyzed"""
        return self.what

    def setWhat(self, what):
        """Set the object to analyze
            :param what is the object to be analyzed
        """
        self.what = what

    def saveAnalysisToFile(self, path, flag):
        """
        Saves the analysis result to the specified path
        :param flag: if true the analysis will be saved, otherwise it won't
        :param path: the path where to save the analysis
        :return: true if the analysis will be saved, false otherwise
        """
        self.path = path
        self.flag = flag
        return flag

