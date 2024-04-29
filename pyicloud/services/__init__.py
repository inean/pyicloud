"""Services."""

from typing import cast

from pyicloud.models.settings import Settings
from pyicloud.services.account import AccountService
from pyicloud.services.calendar import CalendarService
from pyicloud.services.contacts import ContactsService
from pyicloud.services.drive import DriveService
from pyicloud.services.findmyiphone import FindMyiPhoneServiceManager
from pyicloud.services.photos import PhotosService
from pyicloud.services.reminders import RemindersService
from pyicloud.services.ubiquity import UbiquityService


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
