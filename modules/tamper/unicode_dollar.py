import json

def tamper(payload):
    """
    Replaces only the '$' symbol with its Unicode equivalent (\u0024).
    Example: {"$ne": 1} -> {"\u0024ne": 1}
    """
    if not isinstance(payload, dict):
        return payload
    
    json_str = json.dumps(payload)
    tampered_str = json_str.replace("$", "\\u0024")
    
    return tampered_str