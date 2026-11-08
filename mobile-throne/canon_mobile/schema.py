SCHEMA_VERSION = 2
GENESIS = "0" * 64
ARTICLES = tuple(f"A{i}" for i in range(1, 14))


def require_version(value: int) -> None:
    if type(value) is not int or value != SCHEMA_VERSION:
        raise ValueError(f"schema version {value!r} != canonical {SCHEMA_VERSION}")
