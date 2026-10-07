import uuid, json
from typing import List, Any, Optional

def generate_id(prefix: str = "id") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"

def chunk_list(lst: List[Any], size: int) -> List[List[Any]]:
    return [lst[i:i + size] for i in range(0, len(lst), size)]

def safe_json(obj: Any, default: str = "{}") -> str:
    try:
        return json.dumps(obj, default=str)
    except Exception:
        return default
