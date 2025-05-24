from types import SimpleNamespace
import importlib
import copy
import socket
import os
import argparse

from nettacker.core.utils.huey_config import huey
from nettacker import logger
from nettacker.core.messages import messages as _
from nettacker.core.socks_proxy import set_socks_proxy

log = logger.get_logger()

@huey.task(retries=3, retry_delay=2)
def new_scan_task(form_values):
	from nettacker.core.app import Nettacker
	form_values["targets"] = [form_values["targets"]]
	nettacker_app = Nettacker(api_arguments = SimpleNamespace(**form_values))
	app_arguments = SimpleNamespace(**form_values)

<<<<<<< HEAD
	# Bruh till here everything's fine!
	if not isinstance(app_arguments.selected_modules, list):
		app_arguments.selected_modules = app_arguments.selected_modules.split(",")			# make sure we don't come here if we have actually selected more.
=======
	print("These are the arguments to nettacker: {}".format(app_arguments))			# Is it splitting en.wikipedia.org
	# Bruh till here everything's fine!
	if not isinstance(app_arguments.selected_modules, list):
		app_arguments.selected_modules = [app_arguments.selected_modules]			# make sure we don't come here if we have actually selected more.
>>>>>>> 8b7c9850 (fixed this up, only new_scan_task works well)
	nettacker_app.arguments = app_arguments
	nettacker_app.run()

	return vars(app_arguments)
