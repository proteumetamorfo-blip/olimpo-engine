import os, sys, time, argparse
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.loader import init_db, live_stats

class C:
    RESET="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
    RED="\033[91m"; YELLOW="\033[93m"; GREEN="\033[92m"
    CYAN="\033[96m"; MAGENTA="\033[95m"

def _bar(value, total, width=16):
    filled = min(int((value/total)*width), width) if total else 0
    return f"{C.CYAN}{'█'*filled}{C.DIM}{'░'*(width-filled)}{C.RESET}"

def _ac(level):
    return {
        "CRITICAL": C.RED, "WARNING": C.YELLOW, "OK": C.GREEN
    }.get(level, C.DIM)

def render(stats, refresh_count, interval):
    total = stats["total"] or 1
    ok_n  = stats["total"] - stats["warning"] - stats["critical"]
    now   = datetime.utcnow().strftime("%H:%M:%S UTC")

    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()

    print(f"{C.CYAN}{C.BOLD}{'='*54}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  OLIMPO ENGINE — DASHBOARD{C.RESET}")
    print(f"  {C.DIM}{now} | Refresh #{refresh_count} | Ctrl+C sair{C.RESET}")
    print(f"{C.CYAN}{'='*54}{C.RESET}")

    print(f"\n  {C.BOLD}RESUMO{C.RESET}")
    print(f"  {C.GREEN}●{C.RESET} Eventos     {C.BOLD}{stats['total']:>5}{C.RESET}")
    print(f"  {C.YELLOW}◆{C.RESET} Warning     {C.YELLOW}{C.BOLD}{stats['warning']:>5}{C.RESET}")
    print(f"  {C.RED}▲{C.RESET} Critical    {C.RED}{C.BOLD}{stats['critical']:>5}{C.RESET}")
    print(f"  {C.MAGENTA}◉{C.RESET} Ameacas IDS {C.MAGENTA}{C.BOLD}{stats['threats']:>5}{C.RESET}")
    print(f"  {C.RED}▲{C.RESET} Blacklist   {C.RED}{C.BOLD}{stats['blacklisted']:>5}{C.RESET}")
    print(f"  {C.YELLOW}◆{C.RESET} Quarentena  {C.YELLOW}{C.BOLD}{stats['quarantined']:>5}{C.RESET}")

    print(f"\n  {C.BOLD}DISTRIBUICAO{C.RESET}")
    print(f"  OK       {_bar(ok_n, total)}  {ok_n}")
    print(f"  WARNING  {_bar(stats['warning'], total)}  {stats['warning']}")
    print(f"  CRITICAL {_bar(stats['critical'], total)}  {stats['critical']}")

    if stats["blacklist"]:
        print(f"\n  {C.RED}{C.BOLD}BLACKLIST{C.RESET}")
        for bl in stats["blacklist"]:
            print(f"  {C.RED}>{C.RESET} {C.BOLD}{bl['ip']:<17}{C.RESET} {C.YELLOW}{bl['count']}x{C.RESET} {bl['event_type']}")

    if stats["recent_threats"]:
        print(f"\n  {C.MAGENTA}{C.BOLD}AMEACAS IDS{C.RESET}")
        for t in stats["recent_threats"][:4]:
            sc = C.RED if t["severity"]=="HIGH" else C.YELLOW
            print(f"  {sc}[{t['severity']}]{C.RESET} {C.BOLD}{t['ip']:<16}{C.RESET} {C.MAGENTA}{t['rule']}{C.RESET}")

    print(f"\n  {C.BOLD}ULTIMOS EVENTOS{C.RESET}")
    print(f"  {C.DIM}{'IP':<17} {'EVENTO':<18} ALERTA{C.RESET}")
    for ev in stats["recent_events"][:6]:
        ac = _ac(ev["alert_level"])
        print(f"  {ev['ip']:<17} {ev['event'][:17]:<18} {ac}{ev['alert_level']}{C.RESET}")

    print(f"\n{C.CYAN}{'='*54}{C.RESET}")
    if interval > 0:
        print(f"  {C.DIM}Atualizando em {interval}s | Ctrl+C para sair{C.RESET}")

def run(interval=5, once=False):
    init_db()
    refresh_count = 0
    try:
        while True:
            refresh_count += 1
            stats = live_stats()
            render(stats, refresh_count, interval)
            if once:
                print()
                break
            for _ in range(interval * 2):
                time.sleep(0.5)
    except KeyboardInterrupt:
        print(f"\n\n  {C.GREEN}Dashboard encerrado.{C.RESET}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=int, default=5)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    run(args.interval, args.once)
