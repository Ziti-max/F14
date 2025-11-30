import json

def to_unicode(text):
    """Converts text to full unicode escape sequence"""
    return "".join([f"\\u{ord(c):04x}" for c in text])

def tamper(payload):
    """
    Converts all JSON keys to Unicode escape sequences.
    Example: {"user": "admin"} -> {"\u0075\u0073\u0065\u0072": "admin"}
    """
    json_str = json.dumps(payload)
    
    # Common NoSQL keys and fields to encode
    targets = ["$ne", "$gt", "$where", "$regex", "$expr", "username", "password", "email", "id"]
    
    for t in targets:
        if t in json_str:
            json_str = json_str.replace(f'"{t}"', f'"{to_unicode(t)}"')
            
    return json_str