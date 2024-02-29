from __future__ import annotations

import os
import re
from os import path
from uuid import uuid1

import yaml


class PyiCloudConfig:
    APP_DEFAULT_CONFIG_VALUES = {
        "with_family": True,
        "verify": True,
        "client_id": ("auth-%s" % str(uuid1()).lower()),
    }
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
    def from_file(cls, apple_id: str = ""):
        config_file = path.join(cls.setup_config_dir(), "config.yml")
        return cls._init_from_file(apple_id, config_file)

    @classmethod
    def _init_from_file(cls, apple_id: str = "", config_file=None):
        config_file = config_file or path.join(cls.setup_config_dir(), "config.yml")
        try:
            with open(config_file, encoding="utf-8") as stream:
                return cls(apple_id, config_file, yaml.safe_load(stream))
        except FileNotFoundError:
            return cls(apple_id, config_file)

    def __init__(self, apple_id: str = "", config_file=None, config=None):
        self.apple_id = apple_id
        self._config = config or {}
        self._config_file = config_file
        self._cookie_file = None
        self._session_file = None
        self._keep_in_sync = False

    def __getattr__(self, name):
        try:
            return self._config.get(name, self.APP_DEFAULT_CONFIG_VALUES[name])
        except KeyError as exc:
            if hasattr(self.__class__, name) and isinstance((attr := getattr(self.__class__, name)), property):
                return attr.fget(self)
            # If the name is not a property, raise an AttributeError
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'") from exc

    def __setattr__(self, name, value):
        if name in self.APP_DEFAULT_CONFIG_VALUES:
            self._config[name] = value
            if self._keep_in_sync and self._config_file:
                with open(self._config_file, "w", encoding="utf-8") as stream:
                    yaml.safe_dump(self._config, stream)
            return

        super().__setattr__(name, value)

    def __repr__(self):
        return f"PyiCloudConfig({self._config})"

    def __str__(self):
        return str(self._config)

    @property
    def cookiejar_file(self):
        """Get path for cookiejar file."""
        if not self.apple_id:
            raise ValueError("apple_id is not set")
        self._cookie_file = self._cookie_file or path.join(
            self.setup_cookie_dir(), re.sub(r"\W", "", self.apple_id) + ".cookies"
        )
        return self._cookie_file

    @property
    def session_file(self):
        """Get path for session data file."""
        if not self.apple_id:
            raise ValueError("apple_id is not set")
        self._session_file = self._session_file or path.join(
            self.setup_config_dir(), re.sub(r"\W", "", self.apple_id) + ".session"
        )
        return self._session_file
