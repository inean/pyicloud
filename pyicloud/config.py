from __future__ import annotations

import json
import logging
import os
import re
from abc import ABC, abstractmethod
from http import cookiejar
from os import path
from tkinter import N
from uuid import uuid1

import yaml

LOGGER = logging.getLogger(__name__)


class _CookieJarProxy:
    def __init__(self, cookie_jar):
        self._cookie_jar = cookie_jar

    def __getattr__(self, name):
        try:
            return self._cookie_jar[name].value
        except KeyError:
            pass
        # If the cookie does not exist, delegate to the CookieJar object
        return getattr(self._cookie_jar, name)

    @property
    def mirror(self):
        return self._cookie_jar


class _ConfigProxy:

    CONFIG_VALUES = {
        "with_family": True,
        "verify": True,
        "client_id": ("auth-%s" % str(uuid1()).lower()),
    }

    def __init__(self, dict_obj):
        self._config = dict_obj

    def __getattr__(self, name):
        try:
            return self._config[name]
        except KeyError:
            if name in self.CONFIG_VALUES:
                return self.CONFIG_VALUES[name]
        return getattr(self._config, name)

    def __setattr__(self, name, value):
        if name == "_config":
            super().__setattr__(name, value)
            return
        if name in self.CONFIG_VALUES:
            self._config[name] = value
            return
        setattr(self._config, name, value)

    @property
    def mirror(self):
        return self._config


class _DictProxy:
    def __init__(self, dict_obj):
        self._dict = dict_obj

    def __getattr__(self, name):
        try:
            return self._dict[name]
        except KeyError:
            pass
        return getattr(self._dict, name)

    @property
    def mirror(self):
        return self._dict


class PyiCloudConfig(ABC):
    """Abstract class for PyiCloud configuration."""

    PACKAGE_NAME = "pyicloud"

    # *fmt: off
    BASE_COOKIES = {"dslang": "ES-ES", "site": "ESP"}
    LOGIN_COOKIES = (["aasp"],)
    LOGGED_COOKIES = (
        [
            "acn01",
            "X-APPLE-DS-WEB-SESSION-TOKEN",
            "X-APPLE-UNIQUE-CLIENT-ID",
            "X-APPLE-WEBAUTH-LOGIN",
            "X-APPLE-WEBAUTH-USER",
            "X-APPLE-WEBAUTH-VALIDATE",
            *BASE_COOKIES,
            *LOGIN_COOKIES,
        ],
    )
    FA1_COOKIES = (
        [
            "X-APPLE-WEBAUTH-HSA-LOGIN",
            *BASE_COOKIES,
            *LOGGED_COOKIES,
        ],
    )
    # *fmt: on
    FA2_COOKIES = [
        "X-APPLE-WEBAUTH-FMIP",
        "X-APPLE-WEBAUTH-HSA-TRUST",
        "X-APPLE-WEBAUTH-TOKEN",
        *BASE_COOKIES,
        *LOGGED_COOKIES,
    ]

    def __init__(self, apple_id: str = ""):
        self._apple_id: str = apple_id
        self._password: str = ""

        self._config: _ConfigProxy | None = None
        self._session: _DictProxy | None = None
        self._cookies: _CookieJarProxy | None = None

    @classmethod
    @abstractmethod
    def create(cls, apple_id: str, **kwargs):
        """Create a new configuration."""

    @abstractmethod
    def load(self):
        """Load configuration from file."""

    @abstractmethod
    def revert(self):
        """Revert configuration to last saved state."""

    @abstractmethod
    def save(self):
        """Save configuration to file."""

    @property
    @abstractmethod
    def config(self):
        """Get configuration."""

    @property
    @abstractmethod
    def cookies(self):
        """Get cookies."""

    @property
    @abstractmethod
    def session(self):
        """Get session."""

    @property
    def apple_id(self):
        """Get Apple ID."""
        return self._apple_id

    @apple_id.setter
    def apple_id(self, value: str):
        """Set Apple ID."""
        self._apple_id = value


class PyiCloudFileConfig(PyiCloudConfig):

    @classmethod
    def _make_dir(cls, env_var_name, system_env_var_name, default_dir):
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
        default_dir = path.join(default_dir, cls.PACKAGE_NAME)

        dir_path = env_dir or default_dir
        if not os.path.exists(dir_path):
            os.makedirs(dir_path, mode=0o700, exist_ok=True)

        return dir_path

    @classmethod
    def _cache_dir(cls):
        cookie_params = {
            "env_var_name": f"{cls.PACKAGE_NAME.upper()}_COOKIE_DIR",
            "system_env_var_name": "XDG_CACHE_HOME",
            "default_dir": "cache",
        }
        return cls._make_dir(**cookie_params)

    @classmethod
    def _config_dir(cls):
        config_params = {
            "env_var_name": f"{cls.PACKAGE_NAME.upper()}_CONFIG_DIR",
            "system_env_var_name": "XDG_CONFIG_HOME",
            "default_dir": "config",
        }
        return cls._make_dir(**config_params)

    @classmethod
    def create(cls, apple_id: str = "", config_file: str = "", cookie_file: str = "", session_file: str = ""):
        return cls(apple_id, config_file, cookie_file, session_file)

    def __init__(self, apple_id: str = "", config_file: str = "", cookie_file: str = "", session_file: str = ""):
        PyiCloudConfig.__init__(self, apple_id)
        self.__config_file: str = config_file
        self.__cookie_file: str = cookie_file
        self.__session_file: str = session_file

    def __repr__(self):
        return f"PyiCloudConfig({self._config})"

    def __str__(self):
        return str(self._config)

    def _load_config(self):
        try:
            with open(self._config_file, encoding="utf-8") as stream:
                return yaml.safe_load(stream)
        except FileNotFoundError:
            return {}

    def _load_session(self):
        try:
            LOGGER.debug("Using session file %s", self.__session_file)
            with open(self.__session_file, encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            LOGGER.error("Session file is not a valid JSON file")
        except OSError:
            LOGGER.info("Session file does not exist")
        return {}

    def _load_cookies(self):
        try:
            LOGGER.debug("Using cookiejar file %s", self._cookiejar_file)
            lwp_cookie_jar = cookiejar.LWPCookieJar(self._cookiejar_file)
            lwp_cookie_jar.load(ignore_discard=True, ignore_expires=True)
            return lwp_cookie_jar
        except FileNotFoundError:
            LOGGER.info("Failed to read cookiejar %s", self._cookiejar_file)
            return cookiejar.LWPCookieJar()  # create an empty cookie jar

    @property
    def _cookiejar_file(self):
        """Get path for cookiejar file."""
        if not self.apple_id:
            raise ValueError("apple_id is not set")
        self.__cookie_file = self.__cookie_file or path.join(
            self._cache_dir(), re.sub(r"\W", "", self.apple_id) + ".cookies"
        )
        return self.__cookie_file

    @property
    def _session_file(self) -> str:
        """Get path for session data file."""
        if not self.apple_id:
            raise ValueError("apple_id is not set")
        self.__session_file = self.__session_file or path.join(
            self._config_dir(), re.sub(r"\W", "", self.apple_id) + ".session"
        )
        return self.__session_file

    @property
    def _config_file(self) -> str:
        """Get path for configuration file."""
        if not self.__config_file:
            self.__config_file = path.join(self._config_dir(), f"{self.PACKAGE_NAME}.yml")
        return self.__config_file

    @property
    def config(self) -> _ConfigProxy:
        if self._config is None:
            self._config = _ConfigProxy(self._load_config())
        return self._config

    @property
    def session(self) -> _DictProxy:
        if self._session is None:
            if not (session := self._load_session()):
                session = {"client_id": self.config.client_id}
            self._session = _DictProxy(session)
        return self._session

    @property
    def cookies(self) -> _CookieJarProxy:
        if self._cookies is None:
            cookies = self._load_cookies()
            self._cookies = _CookieJarProxy(cookies)
        return self._cookies

    def load(self):
        return [value.mirror for value in (self.config, self.session, self.cookies)]

    def revert(self):
        raise NotImplementedError

    def save(self):
        raise NotImplementedError
