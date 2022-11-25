"""
Define the required entry-points functions in order for Salt to know
what and from where it should load this extension's loaders
"""
from . import PACKAGE_ROOT  # pylint: disable=unused-import,no-name-in-module


def get_states_dirs():
    """
    Return a list of paths from where salt should load state modules
    """
    return [str(PACKAGE_ROOT / "_states")]
