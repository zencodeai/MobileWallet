import uuid
from datetime import datetime, timezone


class OBPClientRoot(object):
    # OBP client root class
    pass


def get_time_now() -> str:
    # Get current time
    return datetime.now(timezone.utc).strftime('%G-%m-%dT%H:%M:%SZ')


def is_valid_uuid(uuid_to_test: str, version: int = 4) -> bool:
    # Check if uuid is valid
    try:
        uuid_obj = uuid.UUID(uuid_to_test, version=version)
    except ValueError:
        return False
    return str(uuid_obj) == uuid_to_test


def sanitize(data: str) -> str:
    # Sanitize json data containing reserved keywords
    for e in [('list', 'list_'), ('from', 'from_')]:
        data = data.replace(f'"{e[0]}":', f'"{e[1]}":')
    return data
