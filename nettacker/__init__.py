import hydra
import yaml
from omegaconf import OmegaConf

from nettacker.config import Config


class HydraConfigs:
    @staticmethod
    def get_config(library, category):
        path = f"modules/{category}"
        with hydra.initialize(config_path=path, version_base="1.1"):
            cfg = hydra.compose(config_name=library, overrides=[])
        return cfg

    @staticmethod
    def get_attack_config(library, category, user_inputs):
        path = f"modules/{category}"
        with hydra.initialize(config_path=path, version_base="1.1"):
            cfg = hydra.compose(config_name=library, overrides=[])

        raw_yaml = OmegaConf.to_yaml(cfg)
        formatted_yaml = raw_yaml.format(**user_inputs)
        # formatted_yaml = formatted_yaml.replace('__dollars__', '$')
        return yaml.safe_load(formatted_yaml)

    @staticmethod
    def get_normal_config(library, category):
        with open(Config.path.modules_dir / category / f"{library}.yaml") as yaml_file:
            return yaml_file.read()
