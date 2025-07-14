import copy

from huey import SqliteHuey, RedisHuey

from nettacker.config import Config


def get_huey_instance():
    configs = Config.huey.as_dict()
    use_redis = copy.deepcopy(configs["huey_redis"])
    del configs["huey_redis"]

    if use_redis:
        huey = RedisHuey(**configs)

    huey = SqliteHuey(**configs)

    return huey
