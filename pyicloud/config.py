from __future__ import annotations

import os
from os import path

import yaml


class PyiCloudConfig:
    APP_NAME = "pyicloud"

    @classmethod
    def _setup_dir(cls, env_var_name, system_env_var_name, default_dir):
        # try to find locally first. Run recursively from current dir to rootdir
        # looking for {appname} fdir. If found, use it.
        dir_path = os.getcwd()
        while dir_path not in {path.abspath(os.sep), ""}:
            candidate_path = path.join(dir_path, default_dir)
            if path.isdir(candidate_path):
                return candidate_path
            dir_path = path.dirname(dir_path)

        # Compute the directory path from env
        env_dir = os.getenv(env_var_name, "")
        env_dir = path.expanduser(os.path.normpath(env_dir))

        # Compute default system directory path
        default_dir = os.getenv(system_env_var_name, f"~/.{default_dir}")
        default_dir = path.expanduser(path.normpath(default_dir))
        default_dir = path.join(default_dir, cls.APP_NAME)

        dir_path = env_dir or default_dir
        if not os.path.exists(dir_path):
            os.makedirs(dir_path, mode=0o700, exist_ok=True)

        return dir_path

    @classmethod
    def setup_cookie_dir(cls):
        cookie_params = {
            "env_var_name": "PYICLOUD_COOKIE_DIR",
            "system_env_var_name": "XDG_CACHE_HOME",
            "default_dir": "cache",
        }
        return cls._setup_dir(**cookie_params)

    @classmethod
    def setup_config_dir(cls):
        config_params = {
            "env_var_name": "PYICLOUD_CONFIG_DIR",
            "system_env_var_name": "XDG_CONFIG_HOME",
            "default_dir": "config",
        }
        return cls._setup_dir(**config_params)

    @classmethod
    def from_file(cls):
        config_file = path.join(cls.setup_config_dir(), "config.yml")
        return cls._init_from_file(config_file)

    @classmethod
    def _init_from_file(cls, config_file=None):
        config_file = config_file or path.join(cls.setup_config_dir(), "config.yml")
        try:
            with open(config_file, encoding="utf-8") as stream:
                return cls(yaml.safe_load(stream), config_file)
        except FileNotFoundError:
            return cls({}, config_file)

    def __init__(self, config, config_file=None):
        self._config = config
        self._config_file = config_file

    def __getattr__(self, name):
        try:
            return self._config[name]
        except KeyError as exc:
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'") from exc

    def __setattr__(self, name, value):
        if not name.startswith("_") and name in self._config:
            self._config[name] = value
            with open(self.config_file, "w", encoding="utf-8") as stream:
                yaml.safe_dump(self._config, stream)
        else:
            super().__setattr__(name, value)

    def __repr__(self):
        return f"PyiCloudConfig({self._config})"

    def __str__(self):
        return str(self._config)
