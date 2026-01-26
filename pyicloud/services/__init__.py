"""Services."""

from __future__ import annotations

import asyncio
import random
import string
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from itertools import chain
from typing import Any, Awaitable, Callable, ClassVar, Literal, TypedDict, cast, overload

from httpx import AsyncClient
from pydantic import BaseModel

from pyicloud.log import LOGGER
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.paths import CookiesJar
from pyicloud.services.account import AccountService
from pyicloud.services.calendar import CalendarService
from pyicloud.services.contacts import ContactsService
from pyicloud.services.drive import DriveService
from pyicloud.services.findmyiphone import FindMyiPhoneServiceManager
from pyicloud.services.photos import PhotosService
from pyicloud.services.reminders import RemindersService
from pyicloud.services.ubiquity import UbiquityService
from pyicloud.trees import BehaveTree


class PyiCloudServices:
    """
    A base authentication class for the iCloud service. Handles the
    authentication required to access iCloud services.

    Usage:
        from pyicloud import PyiCloudService
        pyicloud = PyiCloudService('username@apple.com', 'password')
        pyicloud.iphone.location()
    """

    class _Proxy:
        def __init__(self, cls, service, endpoint, params):
            self._endpoint = endpoint
            self._service = service
            self._params = params
            # Private Props
            self.__cls = cls
            self.__target = None

        def authenticate(self):
            """Authenticate the service."""
            self._endpoint.authenticate(service=self._service)
            self.__target = self.__cls(self._endpoint[self._service], **self._params)

        def __getattr__(self, name):
            if not self.__target:
                raise Exception("You must authenticate before accessing this attribute.")
            return getattr(self._service, name)

        def __getitem__(self, name):
            if not self.__target:
                raise Exception("You must authenticate before accessing this attribute.")
            return self.__target[name]

    def __init__(self, endpoint):
        self._endpoint = endpoint
        # Expensive services
        self._drive = None
        self._photos = None
        self._files = None

    @property
    def devices(self):
        """Returns all devices."""
        cls = FindMyiPhoneServiceManager
        service = "findme"
        kwargs = {
            "session": self._endpoint.session,
            "params": self._endpoint.params,
            "with_family": cast(Settings, self._endpoint.config).account.with_family,
        }
        if service not in self._endpoint:
            return self._Proxy(cls, service, self._endpoint, kwargs)
        return cls(self._endpoint[service], **kwargs)

    @property
    def iphone(self):
        """Returns the iPhone."""
        return self.devices[0]

    @property
    def account(self):
        """Gets the 'Account' service."""
        cls = AccountService
        service = "account"
        kwargs = {
            "service_root": self._endpoint[service],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
        }
        if service not in self._endpoint:
            return self._Proxy(cls, service, self._endpoint, kwargs)
        return cls(**kwargs)

    @property
    def files(self):
        """Gets the 'File' service."""
        cls = UbiquityService
        service = "ubiquity"
        kwargs = {
            "service_root": self._endpoint[service],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
        }
        if service not in self._endpoint:
            return self._Proxy(cls, service, self._endpoint, kwargs)
        self._files = cls(**kwargs)
        return self._files

    @property
    def photos(self):
        """Gets the 'Photo' service."""
        cls = PhotosService
        service = "ckdatabasews"
        kwargs = {
            "service_root": self._endpoint[service],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
        }
        if service not in self._endpoint:
            return self._Proxy(cls, service, self._endpoint, kwargs)
        self._photos = cls(**kwargs)
        return self._photos

    @property
    def calendar(self):
        """Gets the 'Calendar' service."""
        cls = CalendarService
        service = "calendar"
        kwargs = {
            "service_root": self._endpoint[service],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
        }
        if service not in self._endpoint:
            return self._Proxy(cls, service, self._endpoint, kwargs)
        return cls(**kwargs)

    @property
    def contacts(self):
        """Gets the 'Contacts' service."""
        cls = ContactsService
        service = "contacts"
        kwargs = {
            "service_root": self._endpoint[service],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
        }
        if service not in self._endpoint:
            return self._Proxy(cls, service, self._endpoint, kwargs)
        return cls(**kwargs)

    @property
    def reminders(self):
        """Gets the 'Reminders' service."""
        cls = RemindersService
        service = "reminders"
        kwargs = {
            "service_root": self._endpoint[service],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
        }
        if service not in self._endpoint:
            return self._Proxy(cls, service, self._endpoint, kwargs)
        return cls(**kwargs)

    @property
    def drive(self):
        """Gets the 'Drive' service."""
        cls = DriveService
        service = "drivews"
        kwargs = {
            "service_root": self._endpoint[service],
            "document_root": self._endpoint["docws"],
            "session": self._endpoint.session,
            "params": self._endpoint.params,
        }
        if service not in self._endpoint:
            return self._Proxy(cls, service, self._endpoint, kwargs)
        self._drive = cls(**kwargs)
        return self._drive

    def __str__(self):
        return f"iCloudFactory API: {self._endpoint.apple_id}"

    def __repr__(self):
        return f"<{self}>"


class Service:
    _application: Application
    _url: str
    _status: str

    def __init__(self, application, *, url: str, status: str):
        self._application = application
        self._url = url
        self._status = status


class FindMyiPhone(Service):
    class DeviceInfo(TypedDict):
        name: str
        deviceDisplayName: str
        location: str
        batteryLevel: str
        batteryStatus: str
        deviceClass: str
        deviceModel: str

    class Device:
        # Private Props
        _data: Any
        _info: FindMyiPhone.DeviceInfo | None = None

        def __dir__(self) -> Iterable[str]:
            return chain(super().__dir__(), FindMyiPhone.DeviceInfo.__annotations__.keys())

        def __getattr__(self, name: str) -> Any:
            if name in self.DeviceInfo.__annotations__:
                raise AttributeError(f"Attribute {name} doesn't exists")
            if self._info is None:
                raise AttributeError(f"Attribute {name} not ready yet")
            return self._info[name]

        async def content(self) -> FindMyiPhone.DeviceInfo:
            """Get content."""

            def _random_string(length):
                letters = string.ascii_lowercase
                return "".join(random.choice(letters) for _ in range(length))

            self._info = FindMyiPhone.DeviceInfo(
                name=_random_string(10),
                deviceDisplayName=_random_string(10),
                location=_random_string(20),
                batteryLevel=str(random.randint(0, 100)),
                batteryStatus=random.choice(["Charging", "Discharging", "Full", "Not charging"]),
                deviceClass=random.choice(["Desktop", "Laptop", "Smartphone", "Tablet"]),
                deviceModel=random.choice(["Model A", "Model B", "Model C", "Model D"]),
            )

            await asyncio.sleep(0.1)
            return self._info

    def __iter__(self) -> Iterator[Device]:
        # Application controls http session, so we pass a Endpoint + Params + Body, and optionally a Schema Response
        # endpoint = ...
        # params   = ...
        # body     = ...
        # schema   = ...
        # response = await endpoint.request(params=params, body=body, schema=schema)
        # for device in self.application.devices:
        #    yield self.Device(data=device)
        yield self.Device()
        yield self.Device()


class ApplicationError(Exception): ...


class ApplicationConfig(TypedDict, total=False):
    """
    Configuration for the behavior tree.
    """

    client: type[AsyncClient] | Callable[..., AsyncClient]
    """Type of HTTPX Async client."""

    client_options: dict[str, Any]
    """Options for the HTTPX Async client, represented as a dictionary of strings to any value."""


class Application:
    class ServiceEntry(TypedDict):
        # Name of the service
        name: str
        # Class that implements the service
        klass: type[Service]

    __slots__ = ("settings", "cookies", "api")

    cookies: Cookies
    """Cookies for the model."""

    settings: Settings
    """Settings for the model."""

    api: dict[str, Any]

    application_config: ClassVar[ApplicationConfig] = {}
    """Configuration for the behavior tree."""

    # Registered services
    _services: ClassVar[dict[str, ServiceEntry]] = {}

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        new_config = ApplicationConfig(
            client=AsyncClient,
            client_options={},
        )
        new_config.update(kwargs.get("application_config", cls.application_config or {}))
        cls.application_config = new_config

    def __init__(self, api: Any, *, settings: Settings, cookies: Cookies | None = None):
        username = settings.account.username
        assert username, "Username is required"
        # Load cookies from jar if no cookies is set
        cookies = cookies or cast(Cookies, CookiesJar(Cookies({})).loads(username=username))
        self.settings, self.cookies, self.api = settings, cookies, api

    def __dir__(self) -> Iterable[str]:
        return chain(super().__dir__(), self._services.keys())

    def __getattr__(self, name: str) -> Any:
        return self._create_service(name, api=self.api)

    @overload
    def _create_service(self, service: str, *, api: dict[str, Any]) -> Service: ...

    @overload
    def _create_service(self, service: str, *, url: str, status: Literal["active"]) -> Service: ...

    def _create_service(self, service: str, **kwargs) -> Service:
        # Check if service is registered
        if (entry := self._services.get(service)) is None:
            raise ApplicationError(f"Service {service} not found")

        # Validate application api
        if api := kwargs.get("api", None):
            assert "webservices" in api, "Invalid api format"
            assert entry["name"] in api["webservices"], f'Service {entry["name"]} not authenticated'
            return self._create_service(service, **api["webservices"][entry["name"]])

        # Validate service status
        if (url := kwargs.get("url", None)) is None:
            raise ApplicationError(f"Service {service} not authenticated (missing URL)")
        if (status := kwargs.get("status", None)) != "active":
            raise ApplicationError(f"Service {service} not authenticated (status {status})")

        # Create service
        return entry["klass"](self, url=url, status=status)

    @property
    def client(self) -> AsyncClient:
        options = self.application_config.get("client_options", {})
        session = self.application_config.get("client", AsyncClient)
        return session(**options)

    @classmethod
    def register(cls, service: str, *, name: str, klass: type[Service]) -> None:
        """Register a service."""
        assert service not in cls._services, f"Service {service} already registered"
        cls._services[service] = cls.ServiceEntry(name=name, klass=klass)
        LOGGER.debug(f"Service {service} registered")


# Register services
Application.register("devices", name="findme", klass=FindMyiPhone)
