import json

def to_unicode(text):
    return "".join([f"\\u{ord(c):04x}" for c in text])

def tamper(payload):
    """
    Encodes specific string values into Unicode escape sequences.
    Example: {"user": "admin"} -> {"user": "\u0061\u0064\u006d\u0069\u006e"}
    """
    json_str = json.dumps(payload)
    
    # Sensitive values to encode
    sensitive_values = ["admin", "root", "true", "1234", "return", "success"]
    
    for val in sensitive_values:
        if val in json_str:
            json_str = json_str.replace(f'"{val}"', f'"{to_unicode(val)}"')
            
    return json_str