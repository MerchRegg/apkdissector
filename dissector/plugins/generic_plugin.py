from abc import ABCMeta, abstractmethod


class DissectorPlugin:

    __metaclass__ = ABCMeta

    """This is an abstract class to implement creating a new plugin
        Attributes:
         :param _what the object to analyze
         :type _what dictates which plugin to run when analyzing
    """

    def __init__(self, what, path=""):
        """
        Creates a new instance of a dissector plugin
        :param what: the object to be analyzed
        :param path: the path to the file to save the analysis result
        :param analysis: where is store the analysis done
        """
        self.what = what
        self.path = path
        self.analysis = None

    @abstractmethod
    def analyze(self):
        """
        This method should analyze the what object and return a result object
        :return: the result object
        """
        pass

    def get_what(self):
        """Get the object to be analyzed"""
        return self.what

    def set_what(self, what):
        """Set the object to analyze
            :param what is the object to be analyzed
        """
        self.what = what

    def get_analysis(self):
        """
        Get the analysis done
        :return: the analysis done
        """
        return self.analysis

    @abstractmethod
    def save_analysis_to_file(self, path):
        """
        Saves the analysis result to the specified path
        :param path: the path where to save the analysis
        """
        self.path = path
        pass

