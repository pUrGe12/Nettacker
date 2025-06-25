from multiprocessing import Manager

# This is to store the progress of each scan.
# It takes the scan_id as a key, and stores another dictionary as the value.
# The innner dict holds the number of scans completed and their total number
dict_manager = Manager()
scan_progress = dict_manager.dict()
