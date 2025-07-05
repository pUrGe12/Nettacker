_shared_dict = None
_shared_manager = None

def set_shared_dict(d):
    global _shared_dict
    _shared_dict = d

def get_shared_dict():
    return _shared_dict

def set_shared_manager(d):
    global _shared_manager
    _shared_manager = d

def get_shared_manager():
    return _shared_manager