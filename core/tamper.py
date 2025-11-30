import importlib
import sys
from core.logger import Logger

# اولویت اجرا (هرچه عدد کوچکتر، زودتر اجرا می‌شود)
# 10-30: Logic Changes
# 40-60: Whitespace/Structure
# 70-90: Encoding (Must be last)
PRIORITIES = {
    "logic_inversion": 10,
    "js_concat": 20,
    
    "random_whitespace": 40,
    "space_to_newline": 50,
    "space_to_tab": 50,
    
    "unicode_dollar": 70,
    "unicode_keys": 80,
    "unicode_values": 80,
    "unicode_random": 85,
    "ascii_hex_encoding": 90
}

# تمپرهایی که نباید با هم استفاده شوند
CONFLICTS = {
    "space_to_newline": ["space_to_tab"],
    "space_to_tab": ["space_to_newline"],
    "unicode_keys": ["unicode_random"], # تداخل در انکدینگ
    "unicode_random": ["unicode_keys"]
}

class TamperManager:
    def __init__(self, tamper_names_str):
        self.logger = Logger()
        self.tampers = []
        
        if tamper_names_str:
            self.load_tampers(tamper_names_str)

    def load_tampers(self, names_str):
        names = [n.strip() for n in names_str.split(",")]
        
        # 1. بررسی تداخل‌ها
        for name in names:
            if name in CONFLICTS:
                for conflict in CONFLICTS[name]:
                    if conflict in names:
                        self.logger.warning(f"Conflict detected: '{name}' and '{conflict}' shouldn't be used together. Results may break.")

        loaded_modules = []
        
        for name in names:
            try:
                module_path = f"modules.tamper.{name}"
                module = importlib.import_module(module_path)
                
                if hasattr(module, 'tamper'):
                    priority = PRIORITIES.get(name, 50) # پیش‌فرض وسط
                    loaded_modules.append({
                        "name": name,
                        "func": module.tamper,
                        "priority": priority
                    })
                else:
                    self.logger.error(f"Script '{name}' missing tamper() function.")
            
            except ImportError:
                self.logger.error(f"Tamper script not found: {name}")
            except Exception as e:
                self.logger.error(f"Error loading tamper '{name}': {e}")

        # 2. مرتب‌سازی هوشمند بر اساس اولویت
        # این خط جادویی است: لیست را بر اساس عدد priority سورت می‌کند
        self.tampers = sorted(loaded_modules, key=lambda x: x['priority'])
        
        # نمایش ترتیب اجرا به کاربر
        order_str = " -> ".join([t['name'] for t in self.tampers])
        self.logger.info(f"Tamper Pipeline Constructed: {order_str}")

    def process(self, payload):
        if not self.tampers:
            return payload

        processed_data = payload
        
        for t in self.tampers:
            try:
                processed_data = t["func"](processed_data)
            except Exception as e:
                # self.logger.warning(f"Tamper '{t['name']}' failed: {e}")
                pass
        
        return processed_data