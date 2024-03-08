from __future__ import annotations

import json
import logging
import os
import re
from abc import ABC, abstractmethod
from http.cookiejar import CookieJar, LWPCookieJar
from os import path
from uuid import uuid1

import yaml
from httpx import Cookies

LOGGER = logging.getLogger(__name__)


class _Proxy(ABC):
    def __init__(self, path: str = ""):
        self._path = path

    @property
    def path(self):
        return self._path

    @property
    @abstractmethod
    def matter(self):
        """Get the object to be proxied."""

    @abstractmethod
    def load(self, from_file: str = ""):
        """Load object from file."""

    @abstractmethod
    def save(self, to_file: str = ""):
        """Save object to file."""

    def revert(self):
        """Revert object to last saved state."""
        if self._path:
            self.load(self._path)


class _Cookies(_Proxy):
    def __init__(self, cookies: CookieJar | dict | Cookies = {}, path: str = ""):
        _Proxy.__init__(self, path)
        if isinstance(cookies, Cookies):
            self._cookies = cookies
            self._isowned = False
            return
        # Create a cookie jar from the cookies
        self._cookies = Cookies(cookies)
        self._isowned = True

    def __getattr__(self, name):
        # If the cookie does not exist, delegate to the CookieJar object
        return getattr(self._cookies, name)

    def __setattr__(self, name, value):
        if name.startswith("_") or name in vars(self.__class__).keys():
            super().__setattr__(name, value)
            return
        setattr(self._cookies, name, value)

    def load(self, from_file: str = ""):
        from_file = from_file or self.path
        LOGGER.debug("Using cookiejar file %s", from_file)
        try:
            LOGGER.debug("Read cookies from %s", from_file)
            cookies = LWPCookieJar(filename=from_file)
            cookies.load(ignore_discard=True, ignore_expires=True)
            self._cookies.clear()
            for cookie in cookies:
                self._cookies.jar.set_cookie(cookie)
        except FileNotFoundError:
            LOGGER.info("Failed to read cookiejar %s", from_file)

    def save(self, to_file: str = ""):
        """Save cookies to file."""
        to_file = to_file or self.path
        cookies = LWPCookieJar()
        for cookie in self._cookies.jar:
            cookies.set_cookie(cookie)
        try:
            # Save LWPCookieJar to file
            LOGGER.debug("Saved cookies to %s", to_file)
            cookies.save(filename=to_file, ignore_discard=True, ignore_expires=True)
        except FileNotFoundError:
            LOGGER.warning("Failed to save cookiejar %s", to_file)

    def link(self, value: Cookies):
        """Use an external cookie object"""
        if not self._isowned and self._cookies != value:
            raise RuntimeError("Actually with a borrow cookie Jar")
        self._cookies = value
        self._isowned = False

    def unlink(self):
        """Unlink the cookie object"""
        self._cookies = Cookies()
        self._isowned = True

    @property
    def matter(self):
        return self._cookies


class _ConfigProxy(_Proxy):

    CONFIG_VALUES = {
        "with_family": True,
        "verify": True,
        "client_id": ("auth-%s" % str(uuid1()).lower()),
    }

    def __init__(self, dict_obj, path: str = ""):
        _Proxy.__init__(self, path)
        self._config: dict = dict_obj

    def __getattr__(self, name):
        try:
            return self._config[name]
        except KeyError:
            if name in self.CONFIG_VALUES:
                return self.CONFIG_VALUES[name]
        return getattr(self._config, name)

    def __setattr__(self, name, value):
        if name in ("_path", "_config"):
            super().__setattr__(name, value)
            return
        if name in self.CONFIG_VALUES:
            self._config[name] = value
            return
        setattr(self._config, name, value)

    def load(self, from_file: str = ""):
        from_file = from_file or self.path
        try:
            LOGGER.debug("Using config file %s", from_file)
            with open(from_file, encoding="utf-8") as stream:
                return yaml.safe_load(stream)
        except yaml.YAMLError:
            LOGGER.error("Config file is not a valid Yaml file")
        except (OSError, FileNotFoundError):
            LOGGER.info("Config file does not exist")
        return {}

    def save(self, to_file: str = ""):
        """Update session data."""
        to_file = to_file or self.path
        # Save session_data to file
        with open(to_file, "w", encoding="utf-8") as outfile:
            yaml.dump(to_file, outfile)
            LOGGER.debug("Saved config to %s", to_file)

    @property
    def matter(self):
        return self._config


class _DictProxy(_Proxy):
    def __init__(self, dict_obj, path: str = ""):
        _Proxy.__init__(self, path)
        self._dict: dict = dict_obj

    def __getattr__(self, name):
        try:
            return self._dict[name]
        except KeyError:
            pass
        return getattr(self._dict, name)

    def load(self, from_file: str = ""):
        from_file = from_file or self.path
        try:
            LOGGER.debug("Using session file %s", from_file)
            with open(from_file, encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            LOGGER.error("Session file is not a valid JSON file")
        except OSError:
            LOGGER.info("Session file does not exist")
        return {}

    def save(self, to_file: str = "", data: dict = {}):
        """Update session data."""
        to_file = to_file or self.path
        # Save session_data to file
        with open(to_file, "w", encoding="utf-8") as outfile:
            self._dict.update(data)
            json.dump(to_file, outfile)
            LOGGER.debug("Saved session data to %s", to_file)

    @property
    def matter(self):
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
        self._cookies: _Cookies | None = None

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
            self._config = _ConfigProxy({}, path=self._config_file)
        return self._config

    @property
    def session(self) -> _DictProxy:
        if self._session is None:
            self._session = _DictProxy({"client_id": self.config.client_id}, path=self._session_file)
        return self._session

    @property
    def cookies(self) -> _Cookies:
        if self._cookies is None:
            self._cookies = _Cookies(path=self._cookiejar_file)
        return self._cookies

    def load(self):
        return [v.load() or v for v in (self.config, self.session, self.cookies)]

    def revert(self):
        return [v.revert() or v for v in (self.config, self.session, self.cookies)]

    def save(self):
        return [v.save() or v for v in (self.config, self.session, self.cookies)]
