import os
import json
from core.logger import Logger
from modules.injection.blind_dumper import BlindDumper

class DatabaseEnumerator:
    def __init__(self, requester, url, method, original_data, baseline_response, threads=1, db_type="Generic", prefix="", suffix="", time_sec=None, retries=3):
        self.requester = requester
        self.url = url
        self.method = method
        self.original_data = original_data
        self.baseline = baseline_response
        self.threads = threads
        self.logger = Logger()
        self.db_type = db_type
        self.prefix = prefix
        self.suffix = suffix
        self.time_sec = time_sec
        self.retries = retries
        
        self.templates = self._load_templates()

    def _load_templates(self):
        try:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            payload_path = os.path.join(base_dir, "core", "payloads.json")
            with open(payload_path, "r") as f:
                data = json.load(f)
            
            db_key = "mongodb" if "MongoDB" in self.db_type else "generic"
            return data.get("enumeration_templates", {}).get(db_key, {})
        except Exception as e:
            self.logger.error(f"Failed to load enumeration templates: {e}")
            return {}

    def run(self):
        self.logger.info("Starting Module: Database Enumeration")
        self.get_current_db()

    def get_current_db(self):
        template_name = "current_db"
        
        if template_name not in self.templates:
            self.logger.error(f"Template '{template_name}' not available for {self.db_type}.")
            return

        self.logger.info("Attempting to retrieve 'current_db' name...")
        
        target_expr = self.templates[template_name]
        
        dumper = BlindDumper(
            self.requester, 
            self.url, 
            self.method, 
            self.original_data, 
            self.baseline, 
            threads=self.threads,
            target_expression=target_expr,
            prefix=self.prefix,
            suffix=self.suffix,
            time_sec=self.time_sec,
            retries=self.retries
        )
        dumper.run()