import json, os, sys, time, random, argparse
from datetime import datetime, timezone

OUT_DIR  = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
OUT_FILE = os.path.join(OUT_DIR, "access.json")

LEGIT_IPS   = ["189.28.14.5","177.92.3.10","200.138.12.44","187.45.67.3","201.55.22.8"]
ATTACK_IPS  = {"brute":"45.33.32.156","spam":"198.51.100.8","scan":"89.248.172.16","ua":"104.21.45.33"}
LEGIT_ROUTES = ["/","/sobre","/monumentos","/arsenal","/contato"]
SCAN_ROUTES  = ["/wp-admin","/.env","/phpmyadmin","/admin","/.git/config","/shell.php"]
LEGIT_UAS    = ["Mozilla/5.0 (Linux; Android 13)","Mozilla/5.0 (iPhone; CPU iPhone OS 16_0)"]
BAD_UAS      = ["sqlmap/1.7.8","Nikto/2.1.6","masscan/1.0","python-requests/2.28.0"]

def _ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

def legit():
    return {"ip":random.choice(LEGIT_IPS),"event":"page_view","route":random.choice(LEGIT_ROUTES),"method":"GET","status":200,"user_agent":random.choice(LEGIT_UAS),"timestamp":_ts()}

def contact():
    return {"ip":random.choice(LEGIT_IPS),"event":"contact_submit","route":"/contato","method":"POST","status":200,"user_agent":random.choice(LEGIT_UAS),"timestamp":_ts()}

def brute():
    return {"ip":ATTACK_IPS["brute"],"event":"login_failed","route":"/admin","method":"POST","status":401,"user_agent":random.choice(LEGIT_UAS),"timestamp":_ts()}

def spam():
    return {"ip":ATTACK_IPS["spam"],"event":"contact_submit","route":"/contato","method":"POST","status":200,"user_agent":"python-requests/2.28.0","timestamp":_ts()}

def scan():
    return {"ip":ATTACK_IPS["scan"],"event":"route_scan","route":random.choice(SCAN_ROUTES),"method":"GET","status":404,"user_agent":random.choice(LEGIT_UAS),"timestamp":_ts()}

def bad_ua():
    return {"ip":ATTACK_IPS["ua"],"event":"page_view","route":random.choice(LEGIT_ROUTES),"method":"GET","status":200,"user_agent":random.choice(BAD_UAS),"timestamp":_ts()}

FACTORIES = [legit,contact,brute,spam,scan,bad_ua]
WEIGHTS   = [50,10,15,10,10,5]

os.makedirs(OUT_DIR, exist_ok=True)

parser = argparse.ArgumentParser()
parser.add_argument("--speed", choices=["slow","normal","fast"], default="normal")
args = parser.parse_args()
delays = {"slow":2.0,"normal":0.5,"fast":0.1}
delay  = delays[args.speed]

print(f"Gerando logs em: {OUT_FILE}")
print("Ctrl+C para parar.\n")

count = 0
with open(OUT_FILE, "a", buffering=1) as f:
    try:
        while True:
            event = random.choices(FACTORIES, weights=WEIGHTS, k=1)[0]()
            f.write(json.dumps(event) + "\n")
            count += 1
            tag = "[ATAQUE]" if event["event"] in {"login_failed","route_scan"} else "[  OK  ]"
            print(f"{tag} #{count} {event['ip']:<18} {event['event']}")
            time.sleep(delay)
    except KeyboardInterrupt:
        print(f"\nParado. {count} eventos escritos.")
