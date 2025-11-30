import json
import random

def tamper(payload):
    """
    Injects random whitespace characters (spaces, tabs, newlines) into valid JSON positions.
    """
    if isinstance(payload, (dict, list)):
        json_str = json.dumps(payload)
    else:
        json_str = str(payload)
    
    whitespaces = [" ", "\t", "\n", "\r\n", "  ", "\t\t"]
    new_str = ""
    
    for char in json_str:
        new_str += char
        if char in "{[,:":
            if random.random() > 0.6:
                count = random.randint(1, 3)
                noise = "".join(random.choices(whitespaces, k=count))
                new_str += noise
                
    return new_str