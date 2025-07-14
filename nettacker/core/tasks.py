from types import SimpleNamespace

from nettacker.core.utils.huey_config import get_huey_instance

huey = get_huey_instance()


@huey.task(retries=3, retry_delay=2)
def new_scan_task(form_values):
    from nettacker.core.app import Nettacker

    form_values["targets"] = [form_values["targets"]]
    nettacker_app = Nettacker(api_arguments=SimpleNamespace(**form_values))
    app_arguments = nettacker_app.arguments

    if not isinstance(app_arguments.selected_modules, list) and (
        app_arguments.selected_modules is not None
    ):
        app_arguments.selected_modules = app_arguments.selected_modules.split(",")
    if isinstance(app_arguments.targets, list) and (len(app_arguments.targets) == 1):
        # This means its either multiple targets which are comma seperated or truly a single target
        app_arguments.targets = app_arguments.targets[0].split(",")

    nettacker_app.arguments = app_arguments
    nettacker_app.run()

    return vars(app_arguments)
