import json
import os
import re
from collections import OrderedDict
from pathlib import Path

import pytest
from pydantic import BaseModel

from pyicloud.models.settings import Settings
from pyicloud.paths import AbstractPath, PathConfigDict, PathError, SettingsFile


class SampleModel(BaseModel):
    account: dict[str, str]


class SampleAbstractPath(AbstractPath):
    cls_config = PathConfigDict(
        env_prefix="test_",
        file_origins=OrderedDict(
            {
                "env_file": "CONFIG_FILE",
                "env_dir": "CONFIG_DIR",
                "workspace_dir": ".",
                "system_dir": "HOME/.",
            }
        ),
        file_sub_dir="config",
        pkg_dir="pyicloud",
    )


@pytest.fixture
def username():
    return "user@example.com"


@pytest.fixture
def config_file(username):
    return re.sub(r"\W", "", username) + ".json"


@pytest.fixture
def contents_dict(username: str):
    return {"account": {"username": username}}


@pytest.fixture
def contents_json(contents_dict):
    return json.dumps(contents_dict, separators=(",", ":"))


@pytest.fixture
def contents_model(contents_dict):
    return SampleModel.model_validate(contents_dict)


def test_abstract_file_init_from_dict(contents_dict):
    file = SampleAbstractPath(contents_dict)
    assert file._contents == contents_dict
    assert file._file is None
    assert file._encoding == "utf-8"

    # We can extract file from dict and wans't available at build time
    # so expec an error
    with pytest.raises(PathError):
        os.fspath(file)


@pytest.fixture
def test_file_factory(tmp_path, config_file):
    def _test_file(tmp_path=tmp_path, name=Path(config_file), *, subdirs: tuple | str = "") -> Path:
        # create env file
        subdirs = subdirs if isinstance(subdirs, tuple) else (subdirs,)
        file_ = tmp_path / Path("").joinpath(*subdirs) / name
        file_.parent.mkdir(parents=True, exist_ok=True)
        return file_

    return _test_file


@pytest.fixture
def json_file(test_file_factory, contents_json) -> Path:
    # create env file
    test_file = test_file_factory()
    with test_file.open("w", encoding="utf-8") as f:
        f.write(contents_json)
    return test_file


def test_abstract_file_env_file(contents_dict, json_file: Path, monkeypatch):
    monkeypatch.setenv("TEST_CONFIG_FILE", str(json_file))
    file = SampleAbstractPath(contents_dict)
    # set env var to test absolute_file name extraction
    path = Path(os.fspath(file))
    assert file._file == str(json_file)
    assert path == json_file

    monkeypatch.setenv("TEST_CONFIG_DIR", str(json_file.parent))
    path = Path(os.fspath(file))
    assert file._file == str(json_file)

    monkeypatch.setenv("TEST_CONFIG_FILE", json_file.name)
    path = Path(os.fspath(file))
    assert file._file == json_file.name
    assert path == json_file


@pytest.fixture
def workspace_file(tmp_path, test_file_factory, subdir="subdir") -> tuple[Path, Path, str]:
    # create workspace space
    workspace = Path(tmp_path).joinpath(*[str(i) for i in range(10)])
    workspace.mkdir(parents=True)
    # create config dir into subdir, if any
    test_file = test_file_factory(tmp_path=tmp_path, subdirs=subdir)
    # get tuple
    return workspace, test_file, subdir


@pytest.fixture
def workspace_json_file(workspace_file, contents_json) -> tuple[Path, Path, str]:
    # create workspace space
    [workspace, test_file, sub_dir] = workspace_file
    with test_file.open("w", encoding="utf-8") as f:
        f.write(contents_json)
    return workspace, test_file, sub_dir


def test_abstract_file_working_dir(contents_dict, workspace_json_file: tuple[Path, Path, str]):
    [workspace, test_file, sub_dir] = workspace_json_file
    file = SampleAbstractPath(contents_dict, file=test_file.name)
    assert file._file == test_file.name

    # Set workspace dir to
    file.cls_config["file_origins"]["workspace_dir"] = str(workspace)
    file.cls_config["file_sub_dir"] = sub_dir

    # set env var to test _file name extraction
    path = Path(os.fspath(file))
    assert file._contents == contents_dict
    assert file._file == path.name
    assert path == test_file


def test_abstract_file_fspath(contents_dict, json_file):
    file = AbstractPath(contents_dict, file=str(json_file))
    assert file.__fspath__() == str(json_file)


def test_abstract_file_load(contents_json, json_file):
    file = SampleAbstractPath(file=str(json_file))
    assert contents_json == file.load()


def test_abstract_file_dict_load(contents_dict, json_file):
    # When load, if contents is of same tipe as data_type, update contents and return stored one
    dict_file = SampleAbstractPath(contents_dict, file=str(json_file))
    assert id(contents_dict) == id(dict_file._contents)
    loaded_dict = dict_file.load()
    assert contents_dict == loaded_dict
    assert id(contents_dict) == id(loaded_dict)
    assert id(contents_dict) == id(dict_file._contents)


def test_abstract_file_model_load(contents_model, json_file):
    model_file = SampleAbstractPath(contents_model, file=str(json_file))
    assert id(contents_model) == id(model_file._contents)
    loaded_model = model_file.load()
    assert contents_model == loaded_model
    assert id(contents_model) == id(loaded_model)
    assert id(contents_model) == id(model_file._contents)


def test_abstract_file_save(contents_json, test_file_factory, config_file):
    dest_file = test_file_factory(name=Path(config_file))
    file = SampleAbstractPath(contents_json, file=str(dest_file))
    file.save()
    with dest_file.open("r", encoding="utf-8") as f:
        assert contents_json == f.read()


def test_abstract_file_dict_save(contents_dict, contents_json, test_file_factory, config_file):
    dest_file = test_file_factory(name=Path(config_file))
    file = SampleAbstractPath(contents_dict, file=str(dest_file))
    file.save()
    with dest_file.open("r", encoding="utf-8") as f:
        assert contents_json == f.read()


def test_abstract_file_model_save(contents_model, contents_json, test_file_factory, config_file):
    dest_file = test_file_factory(name=Path(config_file))
    file = SampleAbstractPath(contents_model, file=str(dest_file))
    file.save()
    with dest_file.open("r", encoding="utf-8") as f:
        assert contents_json == f.read()


def test_config_path_fspath(contents_dict, config_file):
    # if no apple_id is set, a value error is  raised
    settings = SettingsFile(Settings.model_construct())
    with pytest.raises(AttributeError):
        os.fspath(settings)
        assert settings._file is None

    # no file set, computed from model
    settings = SettingsFile(Settings.model_validate(contents_dict))
    assert settings._file is None
    # defaults to system dir if config not found in workspace
    path = Path(os.fspath(settings))
    assert path.name == settings._file
    assert settings._file == config_file
    expected_suffix = Path(settings.cls_config["file_sub_dir"]).joinpath(settings._file or "")
    assert path.as_posix().endswith(expected_suffix.as_posix())
    assert path.parent.is_dir()
