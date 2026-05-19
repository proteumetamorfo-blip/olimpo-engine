import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.transformer    import transform
from core.loader         import init_db, load_events, load_blacklist, load_quarantine, load_threats, live_stats
from security.rate_limit import analyze
from security.ids_rules  import scan

print("\n=== OLIMPO ENGINE — TESTE RAPIDO ===\n")

init_db()
print("Banco inicializado.")

with open("data/raw/access.json") as f:
    lines = [json.loads(l) for l in f.readlines()[:100] if l.strip()]

print(f"{len(lines)} eventos carregados.")

clean, quar     = transform(lines)
flagged, bl     = analyze(clean)
enriched, thr   = scan(flagged)

load_events(enriched)
load_blacklist(bl)
load_quarantine(quar)
load_threats(thr)

s = live_stats()
print(f"\n--- RESULTADO ---")
print(f"Total eventos:  {s['total']}")
print(f"Critical:       {s['critical']}")
print(f"Warning:        {s['warning']}")
print(f"Ameacas IDS:    {s['threats']}")
print(f"Blacklist:      {s['blacklisted']}")
print(f"Quarentena:     {s['quarantined']}")

if s['blacklist']:
    print("\n--- BLACKLIST ---")
    for b in s['blacklist']:
        print(f"  IP: {b['ip']} | {b['reason']}")

if s['recent_threats']:
    print("\n--- AMEACAS IDS ---")
    for t in s['recent_threats'][:4]:
        print(f"  [{t['severity']}] {t['ip']} | {t['rule']}")

print("\n=== CONCLUIDO ===\n")
