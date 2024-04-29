"""Library base file."""

from __future__ import annotations

from abc import ABC, abstractmethod
from functools import partial, wraps
from typing import Any, Generic, Self, TypeVar

import async_btree as bt
from pydantic import BaseModel, ConfigDict, Field, model_validator

from pyicloud.log import PyiCloudPasswordFilter
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings
from pyicloud.paths import CookiesJar, SettingsFile


class ModelTree(BaseModel, ABC):
    model_config = ConfigDict(frozen=True)

    settings: Settings = Field(...)
    cookies: Cookies = Field(default_factory=Cookies)

    @model_validator(mode="after")
    def validate_settings(self) -> Self:
        # Add a filter so password is not logged
        PyiCloudPasswordFilter.register(self.settings)
        self.settings.account.events.password.connect(
            partial(PyiCloudPasswordFilter.on_changed_password, context=self.settings)
        )

        # Listen to username updates and reload config if necessary
        self.settings.account.events.username.connect(partial(CookiesJar(self.cookies).loads))
        self.settings.account.events.username.connect(partial(SettingsFile(self.settings).loads))
        self.settings.account.events.username.emit()
        return self

    @property
    def username(self) -> str:
        """Username getter."""
        return self.settings.account.username

    @property
    def password(self) -> str | None:
        """Password getter."""
        password = self.settings.account.password
        return password.get_secret_value() if password else None

    @password.setter
    def password(self, value):
        self.settings.account.password = value

    @property
    def apple_id(self) -> str:
        """Apple ID getter."""
        return self.username

    def __str__(self):
        return f"TreeModel for: ({self.username})"

    def __repr__(self):
        return f"<{self}>"


T = TypeVar("T", bound=ModelTree)


class BehaveTree(bt.BTreeRunner, Generic[T], ABC):
    def __init__(self, model: T, **kwargs):
        bt.BTreeRunner.__init__(self, **kwargs)
        self._model: T = model
        self._btree: bt.AsyncInnerFunction | None = None
        self._cache: dict[str, Any] = {}

    def __enter__(self):
        self._cache = {}
        self._btree = self._setup()
        return super().__enter__()

    def __exit__(self, exc_type, exc, tb):
        super().__exit__(exc_type, exc, tb)
        self._btree = None
        self._cache = {}

    def run(self):
        assert self._btree is not None, "Tree is not setup"
        return bt.BTreeRunner.run(self, self._btree)

    def analyze(self, indent: int = 0, label: str | None = None) -> str:
        if self._btree is None:
            return f"--> {label or 'root'}:"
        return bt.stringify_analyze(bt.analyze(self._btree), indent, label)

    def pull(self, name: str):
        """Store response in context."""

        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                result = await func(*args, **kwargs)
                self._cache[name] = result
                return result

            return wrapper

        return decorator

    def push(self, name: str):
        """Pass variable from context as a keyword argument to func."""

        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                kwargs[name] = self._cache.get(name)
                result = await func(*args, **kwargs)
                return result

            return wrapper

        return decorator

    @abstractmethod
    def _setup(self):
        assert not self._btree, "Tree already setup"

    @property
    def tree(self):
        assert self._btree, "Tree is not setup"
        return self._btree
