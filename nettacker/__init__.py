_shared_dict = None

def set_shared_dict(d):
    global _shared_dict
    _shared_dict = d

def get_shared_dict():
    return _shared_dict
