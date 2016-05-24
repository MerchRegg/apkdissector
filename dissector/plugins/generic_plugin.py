from abc import ABCMeta, abstractmethod


class DissectorPlugin:

    __metaclass__ = ABCMeta

    """This is an abstract class to implement creating a new plugin
        Attributes:
         :param _target the object to analyze
         :type _target dictates which plugin to run when analyzing
    """

    def __init__(self, target, path=""):
        """
        Creates a new instance of a dissector plugin
        :param target: the object to be analyzed
        :param path: the path to the file to save the analysis result
        """
        self.target = target
        self.path = path
        self.analysis = None

    @abstractmethod
    def analyze(self):
        """
        This method should analyze the target object and return a result object
        :return: the result object
        """
        pass

    def get_target(self):
        """Get the object to be analyzed"""
        return self.target

    def set_target(self, target):
        """Set the object to analyze
            :param target is the object to be analyzed
        """
        self.target = target

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