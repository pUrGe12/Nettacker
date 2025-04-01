from collections import defaultdict


def get_probe(index):
	'''
	Backtracing function to find the string in
	data that starts with Probe and returns that
	'''
	for j in data[index::-1]: # traversing backwards
		if j.startswith("Probe"):
			return j
	return None


def get_regexes(index):
	'''
	Forward tracking function to find the strings in
	data that starts with `match` after the index
	until it hits a bunch of hashtags
	'''
	regex_list = []
	for j in data[index:]:
		if j.startswith("match"):
			regex_list.append(j)	# This will add something like `match time m|^[\xd5-\xef]...$|s i/32 bits/` to the list
		elif j.startswith("##############################"):
			break
	return regex_list


def expand_ports(port_range):
	ports_in_between_as_string = ""
	port_i = int(port_range.split("-")[0])
	port_j = int(port_range.split("-")[1])
	real_range = max(port_i, port_j) - min(port_i, port_j)
	for k in range(min(port_i, port_j), min(port_i, port_j) + real_range+1):
		ports_in_between_as_string += str(k)

	return ports_in_between_as_string


def generate_mapping(data):
	# This can probably be memoised cause right now its parsing
	# the same matchings again and again due to the file format
	# of the nmap-service-probes.txt file.

	mapping = defaultdict(lambda: [[], []]) 
	# A dictionary with values as lists. This automatically initializes an empty
	# list in case of a new key. The first list is for the probes, and the second
	# list is to store the matches.

	for index, val in enumerate(data):
		if val.startswith("port") or val.startswith("ports"):
			probe = get_probe(index)
			regex_list = get_regexes(index)
			
			# For each ports, the probe remains the same that we get
			# by backtracing and the matchings remain the same which
			# we get by forward tracing

			for port in val.strip().split(" ")[1].split(","):
				# print(True if "22" in val.strip().split(" ")[1].split(",") else False)
				# This might sometimes be like 1234-1237.
				if not "-" in port:
					mapping[int(port)][0].append(probe)
					mapping[int(port)][1] = regex_list
				else:
					new_expanded_ports = expand_ports(port)
					for new_port in new_expanded_ports:
						mapping[int(new_port)][0].append(probe)
						mapping[int(new_port)][1] = regex_list
	return mapping

with open("/home/purge/nmap-service-probes.txt", "r") as fp:
	data = [line.strip() for line in fp.readlines() if line.startswith != "#"]
	# Shouldn't be a comment, will make parsing faster

mapping = generate_mapping(data)
# This is a dictionary built like this: {key=port_number, value=[[probes], [regexes]]}
# Now save this as a YAML file.

# Note that probe is NOT the actual bytes. Those are there, but this probe list contains
# a lot more things, which will be parsed in the actual program itself.

import yaml

yaml_data = {
    "service_logger": [
        {
            "value": port,
            "probe": probes_regex_full_list[0],
            "regex": probes_regex_full_list[1]
        }
        for port, probes_regex_full_list in mapping.items()
    ]
}

with open("version_probes.yaml", "w") as file:
    yaml.dump(yaml_data, file, default_flow_style=False, sort_keys=False)
