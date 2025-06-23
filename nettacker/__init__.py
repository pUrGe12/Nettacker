from multiprocessing import Manager

# This is to store the progress of each scan.
# It takes the scan_id as a key, and stores another dictionary as the value.
# The innner dict holds the number of scans completed and their total number
dict_manager = Manager()
scan_progress = dict_manager.dict()

# This is a total-targets counter. This is required because
# all the progress calculations are being done inside the lower levels of
# threading, which means they have no idea of how many targets were selected
# as they only work on their single target. But since, this comes under the
# same scan_id, they must be shown to use as a single scan (albeit it being
# a multi-process thing)
int_manager = Manager()
total_targets_selected = int_manager.Value("i", 0)
