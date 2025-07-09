from multiprocessing import Manager

# This allows access to the UDP probes across processes
# This is better than passing the huge probes list as arguments to nettacker
list_manager = Manager()
udp_probes_set = (
    list_manager.dict()
)  # simulate set: keys are probe values, values are dummy (e.g., True)
