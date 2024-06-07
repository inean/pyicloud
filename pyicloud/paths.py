from __future__ import annotations

import json
import os
import re
from os import PathLike, fspath
from pathlib import Path
from typing import ClassVar, Literal, OrderedDict, TypedDict, cast, override

from psygnal import EventedModel
from pydantic import BaseModel, ValidationError

from pyicloud.log import logger_get
from pyicloud.models.cookies import Cookies
from pyicloud.models.settings import Settings

# local deps
from pyicloud.utils.mapping import deep_update


class PathConfigDict(TypedDict):
    env_prefix: str | None
    """A string that is added at the beginning of the environment variable used by this library."""

    file_origins: OrderedDict[Literal["env_file", "env_dir", "workspace_dir", "system_dir"], str]
    """
    An ordered dictionary mapping the origin of a file to its location.
    The order of the keys determines the priority of the locations when searching for a file.
    The keys can be:
    - "env_file": An env path to a file. If the file exists, its path is returned.
    - "env_dir": A env with a path to a directory. If `_file` exists in this directory, its path is returned.
    - "workspace_dir": A string path to a directory. If `_file` exists in this directory or any of its parent directories, its path is returned.
    - "system_dir": A string path to a directory. If `_file` exists in this directory, its path is returned.
    """

    file_sub_dir: str
    """An optional subdir appended to the directory path in `workspace_dir` and `system_dir`."""

    pkg_dir: str
    """The sub dir where the package is installed."""


class PathError(Exception):
    def __init__(self, message: str | None = None):
        super().__init__(message or "Unknown file")


class PathFileError(PathError):
    def __init__(self, path: str, message: str | None):
        self.path = path
        super().__init__(message or f"File error: {path}")


class PathFileNotFoundError(PathFileError):
    def __init__(self, path: str):
        super().__init__(path, f"File not found: {path}")


class PathMissingError(PathFileError):
    def __init__(self, path: str):
        super().__init__(path, f"Missing path for '{path}'")


class AbstractPath[T: BaseModel | dict | str](PathLike):
    __slots__ = ("_contents", "_file", "_encoding")

    cls_config: ClassVar[PathConfigDict] = PathConfigDict(
        env_prefix=None,
        file_origins=OrderedDict(
            {
                "workspace_dir": ".",
            }
        ),
        file_sub_dir="",
        pkg_dir=__name__,
    )

    _contents: T
    _encoding: str
    _file: str | list[str] | None

    def __init__(self, contents: T = "", *, file: str | list[str] | None = None, encoding: str = "utf-8"):
        object.__setattr__(self, "_contents", contents)
        object.__setattr__(self, "_encoding", encoding)
        object.__setattr__(self, "_file", file)

    @override
    def __fspath__(self) -> str:
        def expand_env(value: str) -> Path:
            env = value.split(os.path.sep, 1)
            if root := os.getenv(env[0].upper()):
                return (Path(root) / env[1]) if len(env) > 1 else Path(root)
            return Path(value)

        def find_last_occurrence(
            files: list[str] | str | None, path: Path, *, subdir: str = "", top_down: bool = False
        ) -> Path | None:
            if files:
                files = files if isinstance(files, list) else [files]
                root = Path(path.root)
                subd = Path(subdir)
                # Worspace files MUST exists to be considered
                return_file = None
                for name in files:
                    candidate = Path(name)
                    # If file is absolute, ignore if exists and use it.
                    if candidate.is_absolute():
                        return candidate
                    # If file is relative, search for it
                    candidate = path / subd / name
                    while True:
                        if return_file is None:
                            if (candidate.is_file() or not top_down) or (subdir and candidate.parent.is_dir()):
                                return_file = candidate
                        if not top_down or candidate.parent == (root / subd):
                            break
                        candidate = Path(str(candidate)[: -len(str(subd / candidate.name))]).parent / subd / name
                return return_file

        # if file_origins.env_dir is set, use it
        for origin, value in self.cls_config["file_origins"].items():
            match origin:
                case "env_file" | "env_dir":
                    env = f'{self.cls_config.get("env_prefix", "")}{value}'
                    if env_path := os.environ.get(env.upper()):
                        path = expand_env(env_path).expanduser()
                        if origin == "env_file":
                            object.__setattr__(self, "_file", str(path))
                            continue
                        if origin == "env_dir" and path.is_dir():
                            if candidate_path := find_last_occurrence(self._file, path):
                                return fspath(candidate_path.resolve())

                case "workspace_dir" | "system_dir":
                    path = expand_env(value).expanduser().resolve()
                    if origin == "workspace_dir":
                        subdir = self.cls_config.get("file_sub_dir") or ""
                        if candidate_path := find_last_occurrence(self._file, path, subdir=subdir, top_down=True):
                            return fspath(candidate_path)
                    pkg_dir = self.cls_config["pkg_dir"] or ""
                    if origin == "system_dir":
                        if candidate_path := find_last_occurrence(self._file, path / subdir / pkg_dir):
                            return fspath(candidate_path)

        # Reachede this point, the file is not set
        raise PathError()

    def load(self, **kwargs) -> BaseModel | dict | str:
        # Load the file. If the file parent directory does not exist, create it
        try:
            path = Path(fspath(self))
        except (PathMissingError, PathFileNotFoundError) as err:
            path = Path(err.path)
            path.parent.mkdir(parents=True, exist_ok=True)

        # If a type is not provided, use the type of the contents
        type_ = type(self._contents)

        # Try to cast the contents to the provided type
        with path.open("r", encoding=self._encoding) as f:
            if issubclass(type_, dict):
                deep_update(cast(dict, self._contents), json.load(f))
            elif issubclass(type_, BaseModel):
                try:
                    smodel = cast(BaseModel, self._contents)
                    result = smodel.model_validate_json(f.read(), **kwargs)

                    # EventedModels implement update method to hanle SignalGroups Properly
                    if issubclass(type_, EventedModel):
                        emodel = cast(EventedModel, self._contents)
                        emodel.update(cast(EventedModel, result))
                    else:
                        # Only update well known attributes
                        smodel.__dict__.update(result.__dict__)
                        smodel.__pydantic_fields_set__.update(result.__pydantic_fields_set__)

                except ValidationError as err:
                    logger_get("paths").warning(f"Error loading file '{path}': {err}")
            elif issubclass(type_, str):
                self._contents = f.read()  # type: ignore
            else:
                raise AssertionError(f"Unknown type '{type_}'")
        # Return itself
        return self._contents

    def loads(self, **kwargs) -> BaseModel | dict | str | None:
        try:
            return self.load(**kwargs)
        except FileNotFoundError as err:
            logger_get("paths").warning(f"File not found: {err}")
            return None

    def save(self, **kwargs) -> None:
        # Load the file. If the file parent directory does not exist, create it
        try:
            path = Path(fspath(self))
        except (PathMissingError, PathFileNotFoundError) as err:
            path = Path(err.path)
            path.parent.mkdir(parents=True, exist_ok=True)

        # If a type is not provided, use the type of the contents
        type_ = type(self._contents)

        # Try to cast the contents to the provided type
        with path.open("w", encoding=self._encoding) as f:
            if issubclass(type_, dict):
                json.dump(self._contents, f, separators=(",", ":"))
            elif issubclass(type_, BaseModel):
                f.write(cast(BaseModel, self._contents).model_dump_json(**kwargs))
            elif issubclass(type_, str):
                f.write(self._contents)  # type: ignore
            else:
                raise AssertionError(f"Unknown type '{type_}'")

    def saves(self, **kwargs) -> None:
        try:
            return self.save(**kwargs)
        except FileNotFoundError as err:
            logger_get("paths").error(f"File not found: {err}")
            return None


class SettingsFile(AbstractPath[Settings]):
    cls_config = PathConfigDict(
        env_prefix="pyicloud_",
        file_origins=OrderedDict(
            {
                "env_file": "CONFIG_FILE",
                "env_dir": "CONFIG_DIR",
                "workspace_dir": ".",
                "system_dir": "HOME",
            }
        ),
        file_sub_dir=".config",
        pkg_dir="pyicloud",
    )

    @override
    def __fspath__(self) -> str:
        try:
            return super().__fspath__()
        except PathError as err:
            # If the file is not set, try to use the apple_id as the file name
            if not (username := self._contents.account.username):
                raise AttributeError("apple_id is not set") from err
            self._file = re.sub(r"\W", "", username) + ".json"
            return super().__fspath__()


class CookiesJar(AbstractPath[Cookies]):
    cls_config = PathConfigDict(
        env_prefix="pyicloud_",
        file_origins=OrderedDict(
            {
                "env_file": "COOKIES_FILE",
                "env_dir": "COOKIES_DIR",
                "workspace_dir": ".",
                "system_dir": "HOME",
            }
        ),
        file_sub_dir=".cache",
        pkg_dir="pyicloud",
    )

    @override
    def load(self, username: str, **kwargs):
        if self._file is None:
            self._file = re.sub(r"\W", "", username) + ".jar.json"
        return super().load(**kwargs)

    @override
    def save(self, username: str, **kwargs):
        if self._file is None:
            self._file = re.sub(r"\W", "", username) + ".jar.json"
        return super().save(**kwargs)
