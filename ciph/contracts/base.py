"""
ciph.contracts.base - Foundation for strongly-typed, versioned data contracts.
"""

from typing import Dict, Any, Mapping as TypingMapping, Sequence, Tuple
from collections.abc import Mapping
import json
import hashlib


class ContractValidationError(ValueError):
    """Raised when contract payload does not satisfy formal specification or version constraints."""
    pass


def _unfreeze(val: Any) -> Any:
    """Recursively convert FrozenDict and immutable containers back to standard types."""
    if isinstance(val, FrozenDict):
        return val.to_dict()
    if hasattr(val, "to_dict") and callable(val.to_dict):
        return val.to_dict()
    if isinstance(val, Mapping):
        return {str(k): _unfreeze(v) for k, v in val.items()}
    if isinstance(val, (set, frozenset)):
        return sorted([_unfreeze(x) for x in val], key=lambda x: canonical_json(x))
    if isinstance(val, (list, tuple)):
        return [_unfreeze(x) for x in val]
    return val


def canonical_json(data: Any) -> str:
    """Produce deterministic canonical JSON string."""
    data_unfrozen = _unfreeze(data)
    return json.dumps(data_unfrozen, sort_keys=True, separators=(',', ':'))


class FrozenDict(frozenset, Mapping):
    """
    Deeply immutable mapping type enforcing contract integrity.
    Inherits from (frozenset, Mapping) with empty slots (__slots__ = ()), storing
    elements directly in C-level immutable memory without any mutable external store.
    Blocks object.__setattr__ and dict.__setitem__.
    Recursively freezes all collections upon construction.
    """
    __slots__ = ()

    def __new__(cls, *args, **kwargs):
        if len(args) == 1 and not kwargs and isinstance(args[0], FrozenDict):
            return args[0]
        raw = dict(*args, **kwargs)
        frozen_items = tuple(
            (str(k), freeze_value(v)) for k, v in raw.items()
        )
        return super().__new__(cls, frozen_items)

    @property
    def _items(self) -> Tuple[Tuple[str, Any], ...]:
        return tuple(sorted(super().__iter__(), key=lambda kv: str(kv[0])))

    @property
    def _hash(self) -> int:
        return hash(self._items)

    def __hash__(self) -> int:
        return self._hash

    def __getitem__(self, key: Any) -> Any:
        str_k = str(key)
        for k, v in super().__iter__():
            if k == str_k or k == key:
                return v
        raise KeyError(key)

    def __iter__(self):
        for k, _ in self._items:
            yield k

    def __len__(self) -> int:
        return super().__len__()

    def __contains__(self, key: Any) -> bool:
        str_k = str(key)
        for k, _ in super().__iter__():
            if k == str_k or k == key:
                return True
        return False

    def keys(self) -> Tuple[str, ...]:
        return tuple(k for k, _ in self._items)

    def values(self) -> Tuple[Any, ...]:
        return tuple(v for _, v in self._items)

    def items(self) -> Tuple[Tuple[str, Any], ...]:
        return self._items

    def get(self, key: Any, default: Any = None) -> Any:
        str_k = str(key)
        for k, v in super().__iter__():
            if k == str_k or k == key:
                return v
        return default

    def copy(self) -> "FrozenDict":
        return self

    def __copy__(self) -> "FrozenDict":
        return self

    def __deepcopy__(self, memo: Any) -> "FrozenDict":
        return self

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError(f"'{self.__class__.__name__}' object attributes are read-only")

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"'{self.__class__.__name__}' object attributes are read-only")

    def __setitem__(self, key: Any, value: Any) -> None:
        raise TypeError(f"'{self.__class__.__name__}' object does not support item assignment")

    def __delitem__(self, key: Any) -> None:
        raise TypeError(f"'{self.__class__.__name__}' object does not support item deletion")

    def update(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError(f"'{self.__class__.__name__}' object is immutable")

    def pop(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError(f"'{self.__class__.__name__}' object is immutable")

    def popitem(self) -> None:
        raise TypeError(f"'{self.__class__.__name__}' object is immutable")

    def clear(self) -> None:
        raise TypeError(f"'{self.__class__.__name__}' object is immutable")

    def setdefault(self, key: Any, default: Any = None) -> None:
        raise TypeError(f"'{self.__class__.__name__}' object is immutable")

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, FrozenDict):
            return self._items == other._items
        if isinstance(other, Mapping):
            if len(self) != len(other):
                return False
            for k, v in other.items():
                str_k = str(k)
                if str_k not in self or self[str_k] != v:
                    return False
            return True
        return False

    def __ne__(self, other: Any) -> bool:
        return not (self == other)

    def __repr__(self) -> str:
        return f"FrozenDict({dict(self._items)!r})"

    def __str__(self) -> str:
        return str(dict(self._items))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to regular dict recursively."""
        return {k: _unfreeze(v) for k, v in self._items}


def freeze_value(val: Any) -> Any:
    """Recursively freeze lists, sets, and mappings into immutable tuples, sorted tuples, and FrozenDict."""
    if isinstance(val, FrozenDict):
        return val
    if isinstance(val, Mapping):
        return FrozenDict({k: freeze_value(v) for k, v in val.items()})
    if isinstance(val, (set, frozenset)):
        return tuple(sorted((freeze_value(x) for x in val), key=lambda x: canonical_json(x)))
    if isinstance(val, (list, tuple)):
        return tuple(freeze_value(x) for x in val)
    return val


class VersionedContract:
    """Base class for all versioned data contracts."""
    schema_version: str = "1.0"

