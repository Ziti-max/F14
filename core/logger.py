import sys
from datetime import datetime

class Logger:
    # ANSI Colors List
    G = '\033[92m'  # Green (Success)
    R = '\033[91m'  # Red (Title)
    Y = '\033[93m'  # Yellow (Warning/Joke)
    B = '\033[94m'  # Blue (Info)
    C = '\033[96m'  # Cyan (Jet Body)
    W = '\033[97m'  # White (Subtitle)
    M = '\033[95m'  # Magenta (Dev Name)
    E = '\033[0m'   # End Reset
    
    @staticmethod
    def get_time():
        """برگرداندن زمان فعلی به صورت [HH:MM:SS]"""
        return datetime.now().strftime("%H:%M:%S")

    @staticmethod
    def banner():
        print(f"""{Logger.C}
                                    ,
                                 __-|
                               [    |        __-|
                              ]     |       [    |      {Logger.R}F-14 TOMCAT{Logger.C}
                     _,.-'^^[/-._   |      ]     |      {Logger.W}NoSQL Injection Framework{Logger.C}
                  _/`      ]      ]^'-._   [      |     {Logger.G}v1.0 #Stable{Logger.C}
                .'__       [            '^^]_.-'\\_._
               /      `--"       _            __'.-='^^-.
              /       __.,--' `--.___.-='^^        _.-' {Logger.Y}[!] Target: Mongo-DBS{Logger.C}
             .'      _.,-'   /        \\       =0=  _.-' {Logger.Y}    (Dev was too lazy to add others yet){Logger.C}
            /    _.-' _.-' .'         \\  _.-'^^
           /_.-'  _.-'  _^            _/^^'             {Logger.M}Dev: G0odkid{Logger.C}
        _-'  _.-'     _-'       _,.-='0"0
      .'  _-'      _-'      _,.-^^
    _/ .-'      .-'    _.='
   /_.'      _.-'   _.'
  /`    _,='      i|
 /__,=^^   0"0
{Logger.E}""")

    @staticmethod
    def info(msg):
        # [TIME] [INFO] Message
        print(f"[{Logger.B}{Logger.get_time()}{Logger.E}] {Logger.B}[INFO]{Logger.E} {msg}")

    @staticmethod
    def success(msg):
        # [TIME] [+] Message
        print(f"[{Logger.B}{Logger.get_time()}{Logger.E}] {Logger.G}[+]{Logger.E} {msg}")

    @staticmethod
    def error(msg):
        # [TIME] [-] Message
        print(f"[{Logger.B}{Logger.get_time()}{Logger.E}] {Logger.R}[-]{Logger.E} {msg}")

    @staticmethod
    def warning(msg):
        # [TIME] [!] Message
        print(f"[{Logger.B}{Logger.get_time()}{Logger.E}] {Logger.Y}[!]{Logger.E} {msg}")
    
    @staticmethod
    def test(param, payload):
        """چاپ تست جاری در یک خط جدید با ساعت"""
        print(f"[{Logger.B}{Logger.get_time()}{Logger.E}] {Logger.B}[INFO]{Logger.E} testing parameter '{param}' with payload: {payload}")