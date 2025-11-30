from curl_cffi import requests
import time
import threading
from core.logger import Logger
from core.tamper import TamperManager

class Requester:
    def __init__(self, headers=None, timeout=10.0, proxy=None, is_tor=False, global_delay=0.0, tamper_list=None, retries=3, auth_url=None, auth_data=None, impersonate="chrome120"):
        self.headers = headers or {}
        self.timeout = timeout
        self.retries = retries
        self.auth_url = auth_url
        self.auth_data = auth_data
        self.logger = Logger()
        self.proxy = proxy
        self.is_tor = is_tor
        self.global_delay = global_delay
        self.impersonate = impersonate
        
        self.tamper_manager = None
        if tamper_list:
            self.tamper_manager = TamperManager(tamper_list)
        
        self.proxies = self._setup_proxies()
        
        self._thread_local = threading.local()

        if "Content-Type" not in self.headers:
            self.headers["Content-Type"] = "application/json"

    def _get_session(self):
        if not hasattr(self._thread_local, "session"):
            self._thread_local.session = requests.Session(impersonate=self.impersonate)
            
            if "User-Agent" in self.headers:
                self._thread_local.session.headers["User-Agent"] = self.headers["User-Agent"]
            
        return self._thread_local.session

    def _setup_proxies(self):
        if self.is_tor:
            self.logger.info("Routing traffic through Tor network (SOCKS5://127.0.0.1:9050)")
            return {
                "http": "socks5h://127.0.0.1:9050",
                "https": "socks5h://127.0.0.1:9050"
            }
        elif self.proxy:
            self.logger.info(f"Using Proxy: {self.proxy}")
            return {
                "http": self.proxy,
                "https": self.proxy
            }
        return None

    def _re_login(self):
        session = self._get_session()
        try:
            self.logger.info(f"Attempting to re-login to: {self.auth_url}")
            
            kwargs = {
                "url": self.auth_url,
                "headers": self.headers,
                "verify": False,
                "timeout": self.timeout,
                "proxies": self.proxies
            }
            
            if isinstance(self.auth_data, dict):
                kwargs["json"] = self.auth_data
            else:
                kwargs["data"] = self.auth_data

            resp = session.post(**kwargs)
            
            if resp.status_code == 200:
                self.logger.success("Re-login successful! Session cookies updated.")
                return True
            else:
                self.logger.error(f"Re-login failed with status code: {resp.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Re-login exception: {e}")
            return False

    def send(self, url, method="POST", data=None):
        if self.global_delay > 0:
            time.sleep(self.global_delay)

        final_data = data
        if self.tamper_manager and data is not None:
            final_data = self.tamper_manager.process(data)

        session = self._get_session()

        is_json_request = True
        content_type = self.headers.get("Content-Type", "").lower()
        if "x-www-form-urlencoded" in content_type:
            is_json_request = False
        
        if method == "GET":
            is_json_request = False

        for attempt in range(self.retries + 1):
            try:
                kwargs = {
                    "method": method,
                    "url": url,
                    "headers": self.headers,
                    "verify": False,
                    "timeout": self.timeout,
                    "proxies": self.proxies,
                }

                if method == "GET":
                    kwargs["params"] = final_data if isinstance(final_data, dict) else None
                elif isinstance(final_data, str):
                    kwargs["data"] = final_data
                elif is_json_request:
                    kwargs["json"] = final_data
                else:
                    kwargs["data"] = final_data

                response = session.request(**kwargs)
                
                if self.auth_url and response.status_code in [401, 403]:
                    self.logger.warning(f"Session might be expired (Status {response.status_code}). Triggering Auto-Login...")
                    if self._re_login():
                        continue 

                if response.status_code >= 500:
                    if attempt < self.retries:
                        time.sleep(1)
                        continue
                
                return response
                
            except requests.RequestsError as e:
                if "Timeout" in str(e):
                    self.logger.error(f"Connection timeout! (Attempt {attempt+1}/{self.retries+1})")
                else:
                    self.logger.error(f"Request error: {e} (Attempt {attempt+1}/{self.retries+1})")
                
                if attempt == self.retries:
                    break
            
            except Exception as e:
                self.logger.error(f"Unknown critical error: {e}")
                break
            
            time.sleep(1)
        
        return None