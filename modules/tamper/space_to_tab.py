import json

def tamper(payload):
    """
    Replaces standard JSON whitespace with tabs (\t).
    Example: {"a": 1} -> {"a":\t1}
    """
    if isinstance(payload, (dict, list)):
        json_str = json.dumps(payload)
    else:
        json_str = str(payload)
    
    tampered = json_str.replace(":", ":\t")
    tampered = tampered.replace(",", ",\t")
    tampered = tampered.replace("{", "{\t")
    
    return tampered