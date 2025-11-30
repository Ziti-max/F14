import json

def tamper(payload):
    """
    Replaces standard JSON whitespace with newlines (\n).
    Example: {"a": 1} -> {"a":\n1}
    """
    if isinstance(payload, (dict, list)):
        json_str = json.dumps(payload)
    else:
        json_str = str(payload)
    
    tampered = json_str.replace(":", ":\n")
    tampered = tampered.replace(",", ",\n")
    tampered = tampered.replace("{", "{\n")
    tampered = tampered.replace("}", "\n}")
    
    return tampered