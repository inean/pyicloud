from __future__ import annotations

import re
from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from functools import lru_cache
from typing import (
    Annotated,
    Any,
    ClassVar,
    Literal,
    Self,
    cast,
    get_args,
    get_origin,
    overload,
)

from psygnal import EventedModel
from pydantic import (
    BaseModel,
    ConfigDict,
    SerializationInfo,
    model_serializer,
    model_validator,
)
from pydantic.dataclasses import dataclass
from pydantic.fields import FieldInfo
from pydantic.functional_validators import ModelWrapValidatorHandler

from pyicloud.shared.kernel.context import _init_context_var

type MetaFields = Literal["header", "config", "cookie", "body", "params"]


@dataclass(config=ConfigDict(extra="forbid", frozen=True))
class Meta:
    header: str | None = None
    config: str | None = None
    cookie: str | None = None
    body: str | None = None
    params: str | None = None

    def __iter__(self) -> Iterator[tuple[str, str]]:
        for field in get_args(MetaFields):
            if getattr(self, field) is not None:
                yield field, getattr(self, field)

    def __hash__(self) -> int:
        return hash(tuple(v for _, v in self))

    @lru_cache
    @staticmethod
    def as_header(header: str) -> str:
        header = header.replace("_", "-")
        return "".join(word.lower() for word in re.split("-+", header))

    @lru_cache
    @staticmethod
    def as_cookie(cookie: str) -> str:
        return cookie.replace("_", "-").upper()

    @staticmethod
    def model_dump_meta(
        obj: Any,
        *,
        by_meta: MetaFields,
        include: Sequence[str] | None = None,
        exclude: Sequence[str] | None = None,
        exclude_unset: bool = True,
        exclude_defaults: bool = False,
        exclude_none: bool = True,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        data = data or {}
        fields = getattr(type(obj), "model_fields", None)
        if fields is not None:
            for name, info in cast(Mapping[str, FieldInfo], fields).items():
                # Extract metadata. Pydantic doesn't like unions outside of Annotated
                if not (metadata := info.metadata):
                    try:
                        metadata = cast(Any, info.annotation).__args__[0].__metadata__
                    except AttributeError:
                        metadata = []
                if (meta := next((x for x in metadata if isinstance(x, Meta)), None)) is None:
                    child = getattr(obj, name)
                    if getattr(type(child), "model_fields", None) is not None:
                        data = Meta.model_dump_meta(
                            child,
                            by_meta=by_meta,
                            include=include,
                            exclude=exclude,
                            exclude_unset=exclude_unset,
                            exclude_defaults=exclude_defaults,
                            exclude_none=exclude_none,
                            data=data,
                        )
                    continue
                # Chekc if field satisfieds inclusion requirements
                default = info.get_default(call_default_factory=True)
                current = getattr(obj, name)
                isunset = not hasattr(obj, "model_fields_set") or name not in obj.model_fields_set
                if not info.is_required():
                    if exclude_defaults and current == default:
                        continue
                    if exclude_none and current is None:
                        continue
                    if exclude_unset and isunset:
                        continue

                assert meta
                if target := getattr(meta, by_meta):
                    if include and not (target in include or name in include):
                        continue
                    if exclude and (target in exclude or name in exclude):
                        continue
                    assert target not in data, f"Duplicate key {target} from {obj} found in data"
                    # Handle Special Cases.
                    if hasattr(current, "get_secret_value"):
                        # If the field is a Secret, get the secret value
                        data[target] = current.get_secret_value()
                    else:
                        data[target] = current
        return data

    @staticmethod
    def get_fields(klass: type[BaseModel], field: MetaFields) -> Iterator:
        for name, info in klass.model_fields.items():
            if not (metadata := info.metadata):
                try:
                    metadata = cast(Any, info.annotation).__args__[0].__metadata__
                except AttributeError:
                    metadata = []
            if (meta := next((x for x in metadata if isinstance(x, Meta)), None)) is None:
                child = getattr(klass, name)
                if hasattr(child, "model_fields"):
                    yield from Meta.get_fields(child, field)
                continue
            if target := getattr(meta, field):
                yield target


class ContextModel(BaseModel):
    def __init__(_model_self_, **data: Any) -> None:
        _model_self_.__pydantic_validator__.validate_python(
            data,
            self_instance=_model_self_,
            context=_init_context_var.get(),
        )


class LeafModel(EventedModel):
    def __init__(_model_self_, **data: Any) -> None:
        _model_self_.__pydantic_validator__.validate_python(
            data,
            self_instance=_model_self_,
            context=_init_context_var.get(),
        )
        Group = _model_self_.__signal_group__
        # the type error is "cannot assign to a class variable" ...
        # but if we don't use `ClassVar`, then the `dataclass_transform` decorator
        # will add _events: SignalGroup to the __init__ signature, for *all* user models
        _model_self_._events = Group(_model_self_)  # type: ignore [misc]

    def __getitem__(self, name: str) -> Any:
        return getattr(self, name)

    def __setitem__(self, name: str, value: Any):
        setattr(self, name, value)

    def __contains__(self, name: str) -> bool:
        try:
            self.__getitem__(name)
            return True
        except AttributeError:
            return False

    def __delitem__(self, name: str):
        raise NotImplementedError

    def reset_field(self, field: str, value: Any = None):
        model_fields = cast(Mapping[str, FieldInfo], type(self).model_fields)
        if field in model_fields:
            info = model_fields[field]
            value = value or info.get_default(call_default_factory=True)
            with self.events.blocked():
                # Set to default and remove from model_fields_set
                setattr(self, field, value)
                self.model_fields_set.remove(field)

    @overload
    @classmethod
    def model_fields_from_meta(cls, *, by_meta: MetaFields) -> Iterator[tuple[str, str, FieldInfo]]: ...

    @overload
    @classmethod
    def model_fields_from_meta(
        cls, *, by_meta: Sequence[MetaFields]
    ) -> Iterator[tuple[str, Sequence[str], FieldInfo]]: ...

    @classmethod
    def model_fields_from_meta(
        cls, *, by_meta: MetaFields | Sequence[MetaFields]
    ) -> Iterator[tuple[str, str | Sequence[str], FieldInfo]]:
        by_meta = [by_meta] if isinstance(by_meta, str) else by_meta

        for field, info in cls.model_fields.items():
            assert isinstance(info, FieldInfo)
            if info.metadata:
                metadata = info.metadata
                assert isinstance(metadata, Collection)
            elif get_args(info.annotation):
                annotated = next((arg for arg in get_args(info.annotation) if get_origin(arg) is Annotated), None)
                if annotated is None:
                    continue
                metadata = get_args(annotated)[1:]
            else:
                continue
            for meta in metadata:
                # Skip non meta instance in field Annotations
                if not isinstance(meta, Meta):
                    continue
                # Build value from required meta fields
                value = []
                for meta_field in by_meta:
                    if (v := getattr(meta, meta_field)) is not None:
                        value.append(v)
                # only yield if all required meta fields are present
                if len(value) != len(by_meta):
                    continue
                yield field, value if len(value) > 1 else value[0], info

    @model_validator(mode="wrap")
    @classmethod
    def _wrap(
        cls,
        data: dict[str, Any],
        handler: ModelWrapValidatorHandler[Self],
    ) -> Self:
        fields_set = set()

        for field, info in cls.model_fields.items():
            if field in data:
                continue
            if not info.is_required():
                continue
            field_type = get_args(info.annotation) or (info.annotation,)
            if type(info.default) in field_type or info.default_factory:
                continue
            if factory_method := getattr(cls, f"{field}_default", None):
                data[field] = factory_method()
                fields_set.add(field)
                continue
        # Remove our created defaults from the model_fields_set
        retval = handler(data)
        retval.model_fields_set.difference_update(fields_set)
        return retval

    @model_serializer(mode="wrap")
    def model_serialize(self, handler: Callable, info: SerializationInfo) -> dict[str, Any]:
        # Common case
        by_meta: MetaFields | None = None
        if isinstance(info.context, Mapping) and "by_meta" in info.context:
            by_meta = info.context["by_meta"]
        # Let default handler to serialize types. When done, fetch from that
        data = handler(self)
        if by_meta is None:
            return data
        # Serialize the model fields by meta if provided in context
        assert by_meta in get_args(MetaFields), f"Invalid by_meta: {by_meta}"
        for field, meta, field_info in self.model_fields_from_meta(by_meta=by_meta):
            value = data.pop(field)
            if field_info.exclude:
                continue
            if isinstance(info.exclude, Mapping | Sequence) and field in info.exclude:
                continue
            if isinstance(info.exclude, str) and field == info.exclude:
                continue
            if info.exclude_defaults and field not in self.model_fields_set:
                continue
            if info.exclude_none and value is None:
                continue
            # Split the field alias by '.' to create a nested dictionary
            keys = meta.split(".") if "." in meta else [meta]
            # Reverse the keys to create a nested dictionary
            for key in reversed(keys):
                value = {key: value}
            # Update the data dictionary with the nested dictionary
            data[key] = value[key]
        return data


class NestedModel(LeafModel):
    separator: ClassVar[str] = "."

    def __getitem__(self, name: str):
        def deep_getattr(model, key, sep="."):
            if sep in key:
                key, child_key = key.split(sep, 1)
                return deep_getattr(getattr(model, key), child_key, sep)
            return getattr(model, key)

        # Recursively get the attribute
        return deep_getattr(self, name, self.__class__.separator)

    def __setitem__(self, name: str, value):
        def deep_setattr(model, key, value, sep="."):
            if sep in key:
                key, child_key = key.split(sep, 1)
                deep_setattr(getattr(model, key), child_key, value, sep)
                return

            f_info = cast(Any, type(model)).model_fields[key]
            f_type = get_args(f_info.annotation) or (f_info.annotation,)
            f_type = f_type[0] if len(f_type) == 1 else None
            if f_type is not None and not isinstance(value, f_type):
                # try to cast the value to the field type
                if hasattr(value, "__cast__"):
                    value = value.__cast__(f_type)
                else:
                    raise ValueError(f"Invalid value type: {type(value)} for {name}, expected {f_type}")
                return
            setattr(model, key, value)

        # Recursively set the attribute
        deep_setattr(self, name, value, self.__class__.separator)
