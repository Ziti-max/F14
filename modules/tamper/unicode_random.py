import json
import random

def tamper(payload):
    """
    Randomly encodes characters within JSON strings to Unicode.
    Example: "$ne" -> "\u0024n\u0065"
    """
    if isinstance(payload, (dict, list)):
        json_str = json.dumps(payload)
    else:
        json_str = str(payload)
    
    new_str = ""
    in_string = False
    
    for i, char in enumerate(json_str):
        if char == '"' and (i == 0 or json_str[i-1] != '\\'):
            in_string = not in_string
            new_str += char
            continue
            
        if in_string:
            if random.random() > 0.5:
                new_str += f"\\u{ord(char):04x}"
            else:
                new_str += char
        else:
            new_str += char
            
    return new_str