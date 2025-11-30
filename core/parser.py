import json
from urllib.parse import parse_qsl, urlparse
from core.logger import Logger

class RequestParser:
    def __init__(self):
        self.logger = Logger()

    def parse_file(self, filename):
        """
        Reads raw request file and parses: JSON, Form-Data, or GET Params.
        """
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
            
            if '\r\n\r\n' in content:
                header_part, body_part = content.split('\r\n\r\n', 1)
            elif '\n\n' in content:
                header_part, body_part = content.split('\n\n', 1)
            else:
                header_part = content
                body_part = ""

            lines = header_part.splitlines()
            
            if len(lines) < 1:
                raise ValueError("Request file is empty or invalid")
            
            first_line = lines[0].strip()
            while not first_line and len(lines) > 1:
                lines.pop(0)
                first_line = lines[0].strip()

            request_line_parts = first_line.split()
            if len(request_line_parts) < 2:
                 raise ValueError("Invalid Request Line (Method PATH HTTP/x.x)")

            method = request_line_parts[0].upper()
            path = request_line_parts[1]
            
            headers = {}
            host = ""
            
            for line in lines[1:]:
                line = line.strip()
                if not line: continue
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
                    if key.strip().lower() == "host":
                        host = value.strip()
            
            scheme = "https"
            if host and ("localhost" in host or "127.0.0.1" in host):
                if "443" not in host: scheme = "http"
            
            url = f"{scheme}://{host}{path}"
            
            target_data = {}
            
            if method == "GET":
                parsed_url = urlparse(url)
                if parsed_url.query:
                    target_data = dict(parse_qsl(parsed_url.query))
            
            elif body_part.strip():
                content_type = headers.get("Content-Type", "").lower()
                
                if "application/json" in content_type:
                    try:
                        target_data = json.loads(body_part.strip())
                    except json.JSONDecodeError:
                        self.logger.warning("Body is not valid JSON, trying raw...")
                        target_data = body_part.strip()
                
                elif "application/x-www-form-urlencoded" in content_type:
                    target_data = dict(parse_qsl(body_part.strip()))
                
                else:
                    try:
                        target_data = json.loads(body_part.strip())
                    except:
                        if "=" in body_part:
                            target_data = dict(parse_qsl(body_part.strip()))
                        else:
                            target_data = {}

            return url, method, headers, target_data

        except FileNotFoundError:
            self.logger.error(f"File not found: {filename}")
            exit(1)
        except Exception as e:
            self.logger.error(f"Error parsing file: {e}")
            exit(1)