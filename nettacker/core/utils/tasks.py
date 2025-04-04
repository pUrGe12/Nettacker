import yaml
from nettacker.config import Config
from huey import SqliteHuey

huey = SqliteHuey(filename = Config.path.huey_broker, results = False)

@huey.task(retries=3, retry_delay=2)
def load_yaml_task():
    with open(Config.path.probes_file) as stream:
        data = yaml.safe_load(stream)
    return data
