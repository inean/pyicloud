from __future__ import annotations

import os
import re
import time
import logging
import yaml
import copy

from typing import Iterable
from os import path
from uuid import uuid1
from abc import ABC, abstractmethod
from jinja2 import Environment, BaseLoader
from pymitter import EventEmitter
from httpx import Cookies
from http.cookiejar import CookieJar, LWPCookieJar

# local deps
from . import _dict

LOGGER = logging.getLogger(__name__)


class File(ABC):
    __slots__ = "_path"

    def __init__(self, matter, path: str = ""):
        object.__setattr__(self, "_path", path)

    def __getitem__(self, name):
        return self.matter[name]

    def __setitem__(self, name, value):
        self.matter[name] = value

    def __contains__(self, name):
        return name in self.matter

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value):
        self._path = value

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


class CookieFile(File):
    # *fmt: off
    BASE_COOKIES = {"dslang": "ES-ES", "site": "ESP"}
    LOGIN_COOKIES = ("aasp",)
    LOGGED_COOKIES = (
        "acn01",
        "X-APPLE-DS-WEB-SESSION-TOKEN",
        "X-APPLE-UNIQUE-CLIENT-ID",
        "X-APPLE-WEBAUTH-LOGIN",
        "X-APPLE-WEBAUTH-USER",
        "X-APPLE-WEBAUTH-VALIDATE",
        *BASE_COOKIES,
        *LOGIN_COOKIES,
    )

    FA1_COOKIES = (
        "X-APPLE-WEBAUTH-HSA-LOGIN",
        *BASE_COOKIES,
        *LOGGED_COOKIES,
    )
    # *fmt: on
    FA2_COOKIES = (
        "X-APPLE-WEBAUTH-FMIP",
        "X-APPLE-WEBAUTH-HSA-TRUST",
        "X-APPLE-WEBAUTH-TOKEN",
        *BASE_COOKIES,
        *LOGGED_COOKIES,
    )

    def __init__(self, cookies: CookieJar | dict | Cookies = None, path: str = ""):
        File.__init__(self, path)
        if isinstance(cookies, Cookies):
            self._cookies = cookies
            self._isowned = False
            return
        # Create a cookie jar from the cookies
        self._cookies = Cookies(cookies)
        self._isowned = True

    def fetch(self, cookies: Iterable, domain: str | None = None, path: str | None = None) -> dict | list:
        """Check if a cookie exists and is valid"""
        found, missing, current_time = {}, [], time.time()

        for target in cookies:
            for cookie in self._cookies.jar:
                # Diwscard expired cookies
                if cookie.expires and cookie.expires < current_time:
                    continue
                # Discarrd cookie if name does not match
                if cookie.name != target:
                    continue
                # Discard cookie if domain does not match
                if domain and cookie.domain != domain:
                    continue
                # Discard cookie if path does not match
                if path and cookie.path != path:
                    continue
                found[cookie.name] = cookie.value
                break
            else:
                missing.append(target)
        # Return the found and missing cookies
        return found, missing

    def __getattr__(self, name):
        return getattr(self._cookies, name)

    def load(self, from_file: str = ""):
        """Load cookies from file."""
        from_file = from_file or self.path
        assert from_file, "No cookiejar file specified"
        try:
            LOGGER.debug(f"Read cookies from '{from_file}'")
            cookies = LWPCookieJar(filename=from_file)
            cookies.load(ignore_discard=True, ignore_expires=True)
            self._cookies.clear()
            for cookie in cookies:
                self._cookies.jar.set_cookie(cookie)
        except FileNotFoundError:
            LOGGER.info(f"Failed to read cookiejar '{from_file}'")

    def save(self, to_file: str = ""):
        """Save cookies to file."""
        to_file = to_file or self.path
        assert to_file, "No cookiejar file specified"

        cookies = LWPCookieJar()
        for cookie in self._cookies.jar:
            cookies.set_cookie(cookie)
        try:
            # Save LWPCookieJar to file
            cookies.save(filename=to_file, ignore_discard=True, ignore_expires=True)
            LOGGER.debug(f"Saved cookies to '{to_file}'")
        except FileNotFoundError:
            LOGGER.warning(f"Failed to save cookiejar at '{to_file}'")

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


class SessionFile(File):
    __slots__ = ("_session",)

    def __init__(self, session: dict, path: str = ""):
        File.__init__(self, path)
        self._session = session

    def load(self, from_file: str = ""):
        from_file = from_file or self.path
        assert from_file, "No session file specified"
        try:
            LOGGER.debug("Read session file from '{from_file}")
            with open(from_file, encoding="utf-8") as stream:
                session = yaml.safe_load(stream)
                # update the session data
                session and self._session.update(session)
        except TypeError:
            LOGGER.error("Session file is not a valid Yaml file")
        except yaml.YAMLError:
            LOGGER.error("Session file is not a valid Yaml file")
        except (OSError, FileNotFoundError):
            LOGGER.info(f"Config file '{from_file}' does not exist")

    def save(self, to_file: str = ""):
        """Save session to file"""
        to_file = to_file or self.path
        assert to_file, "No session file specified"

        # Save session_data to file
        with open(to_file, "w", encoding="utf-8") as outfile:
            to_save = copy.copy(self._session)
            for k in PyiCloudConfig.SKIP_KEYS:
                _dict.deep_pop(to_save, k)
            yaml.dump(to_save, outfile)
            LOGGER.debug(f"Saved config to '{to_file}'")

    @property
    def matter(self):
        return self._session


class PyiCloudConfig(ABC):
    """Abstract class for PyiCloud configuration."""

    PACKAGE_NAME = "pyicloud"

    CONFIG_TEMPLATE = """
        username: &username "{{ username }}"
        password: &password "{{ password }}"
        auth:
            token: null
            accountCountryCode: null
            xAppleTwosvTrustToken: null
        twoFactorAuthentication: false
        securityCode: null
        clientSettings:
            language: &language {{ client_settings.language }}
            locale: &locale {{ client_settings.locale }}
            xAppleWidgetKey: "83545bf919730e51dbfba24e7e8a78d2"
            xAppleIDSessionId: null
            xAppleIFDClientInfo:
                U: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.1 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.1"
                L: *locale
                Z: "GMT+02:00"
                V: "1.1"
                F: ""
            timezone: &timezone {{ client_settings.timezone }}
            clientBuildNumber: "2018Project35"
            clientMasteringNumber: "2018B29"
            scnt: null
            defaultHeaders:
                Referer: "https://www.icloud.com/"
                Content-Type: "text/plain"
                Origin: "https://www.icloud.com"
                Host: ""
                Accept: "*/*"
                Connection: "keep-alive"
                Accept-Language: *language
                User-Agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/604.1.25 (KHTML, like Gecko) Version/11.0 Safari/604.1.25"
                Cookie: ""
                X-Requested-With: "XMLHttpRequest"
        clientId: &client_id "{{ clientId }}"
        withFamily: true
        verify: true
        apps: "{{ apps }}"
        push:
            topics: "{{ topics }}"
            token: null
            ttl: 43200
            courierUrl: ""
            registered: []
        account: {}
        logins: []
    """

    SKIP_KEYS = [
        "password",
    ]

    def get(self, key, sep=".", value=None):
        try:
            return _dict.deep_get(self._session, key, sep)
        except KeyError:
            return value

    def __init__(self, username: str = "", **kwargs):
        # Create a Jinja2 environment
        env = Environment(loader=BaseLoader())

        # Load the JSON payload as a Jinja2 template
        template = env.from_string(self.CONFIG_TEMPLATE)

        # Render the template with the session variables
        rendered_template = template.render(
            {
                "username": username,
                "password": kwargs.get("password", ""),
                "client_settings": {
                    "language": kwargs.get("language", "en-us"),
                    "locale": kwargs.get("locale", "en_US"),
                    "timezone": kwargs.get("US/Pacific"),
                    "timeoffset": "GMT+02:00",
                },
                "clientId": kwargs.get("client_id", "auth-%s" % str(uuid1()).lower()),
                "apps": {},
                "topics": [],
            }
        )
        # Load the rendered template as a dictionary
        self._session = SessionFile(yaml.safe_load(rendered_template))
        self._cookies = CookieFile(CookieFile.BASE_COOKIES)
        self._emitter = EventEmitter(wildcard=True)
        self._esilent = False

        # Wait till the username is set
        self.ee.on("changed.username", lambda *_: self.load(update_path=True))

        # Force config load if the username is set
        self["username"] and self.ee.emit("changed.username", None, self["username"])

    def __getitem__(self, name):
        return self._session[name]

    def __setitem__(self, name, value):
        self._session[name], old_value = value, self._session[name]
        if old_value != value and not self._esilent:
            self.ee.emit("changed.{}".format(name), old_value, value)

    def __contains__(self, name):
        return name in self._session

    def __repr__(self):
        return f"PyiCloudConfig({self._session})"

    def __str__(self):
        return str(self._session)

    @abstractmethod
    def load(self):
        """Load configuration from file."""

    @abstractmethod
    def save(self):
        """Save configuration to file."""

    def update(self, entries: dict, silent=False):
        """Update configuration"""
        self._esilent, esilent_state = silent, self._esilent
        try:
            for k, v in _dict.flatten(entries).items():
                self[k] = v
        finally:
            self._esilent = esilent_state

    @property
    def cookies(self) -> CookieFile:
        """Get the cookies file."""
        return self._cookies

    @property
    def ee(self):
        """Get the event emitter."""
        return self._emitter


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

    def __init__(self, username: str = "", config_file: str = "", cookie_file: str = "", **kwargs):
        self._session_path: str = config_file
        self._cookies_path: str = cookie_file
        PyiCloudConfig.__init__(self, username, **kwargs)

    @property
    def _cookies_file(self):
        """Get path for cookiejar file."""
        if not (username := self["username"]):
            raise ValueError("apple_id is not set")
        return self._cookies_path or path.join(self._cache_dir(), re.sub(r"\W", "", username) + ".cookies")

    @property
    def _session_file(self) -> str:
        """Get path for configuration file."""
        if not (username := self["username"]):
            raise ValueError("apple_id is not set")
        return self._session_path or path.join(self._config_dir(), re.sub(r"\W", "", username) + ".session")

    def load(self, update_path: bool = False):
        LOGGER.debug(f"Loading session, cookies from {self._session_file}, {self._cookies_file}")
        self._session.load(self._session_file)
        self._cookies.load(self._cookies_file)
        # On successful load, update the session and cookie paths
        if update_path:
            self._session.path, self._cookies.path = self._session_file, self._cookies_file

    def save(self, update_path: bool = False):
        LOGGER.debug(f"Save session, cookies from {self._session_file}, {self._cookies_file}")
        self._session.save(self._session_file)
        self._cookies.save(self._cookies_file)
        # On successful load, update the session and cookie paths
        if update_path:
            self._session.path, self._cookies.path = self._session_file, self._cookies_file
