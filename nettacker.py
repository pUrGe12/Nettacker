"""OWASP Nettacker application entry point."""

from nettacker.main import run
from nettacker import set_shared_dict, set_shared_manager
from multiprocessing import Manager

if __name__ == "__main__":

    dict_manager = Manager()
    scan_progress = dict_manager.dict()
    set_shared_dict(scan_progress)
    set_shared_manager(dict_manager)
    run()
