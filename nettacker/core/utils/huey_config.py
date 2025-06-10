from huey import SqliteHuey

from nettacker.config import Config

huey = SqliteHuey(filename=Config.path.huey_broker, results=False)
