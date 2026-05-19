"""
core/watcher.py
───────────────
Evolução 1 — Modo Daemon Local Simulado.

Lê o arquivo de log gerado pelo log_generator.py linha a linha,
de forma contínua (equivalente ao `tail -f` do Linux).
Cada linha passa pelo pipeline ETL completo + IDS antes de ser
persistida no SQLite.

Comportamento idêntico ao que seria usado num VPS real com Nginx —
a única diferença é o caminho do arquivo de log.
"""

import os
import time
import json
from datetime import datetime

from core.loader         import init_db, load_events, load_blacklist, load_quarantine, load_threats
from security.rate_limit import analyze
from security.ids_rules  import scan


# ── Configuração ─────────────────────────────────────────────
LOG_PATH       = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "access.json")
FLUSH_INTERVAL = 8       # segundos entre processamentos do buffer
SLEEP_INTERVAL = 0.05    # pausa quando não há novas linhas (segundos)

# ── Cores ANSI ───────────────────────────────────────────────
class C:
    RESET  = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED    = "\033[91m"; YELLOW = "\033[93m"
    GREEN  = "\033[92m"; CYAN   = "\033[96m"


def _wait_for_file(path: str, timeout: int = 30) -> bool:
    """
    Aguarda o arquivo de log ser criado (até `timeout` segundos).
    Útil quando o daemon inicia antes do log_generator.
    """
    print(f"  {C.YELLOW}Aguardando arquivo de log:{C.RESET} {path}")
    for _ in range(timeout * 10):
        if os.path.exists(path):
            return True
        time.sleep(0.1)
    return False


def _flush_buffer(buffer: list[dict]) -> dict:
    """
    Processa um lote de eventos brutos pelo pipeline completo.
    Retorna um resumo do lote para logging.
    """
    if not buffer:
        return {}

    # ── ETL ──────────────────────────────────────────────────
    clean, quarantined = transform(buffer)

    # ── Rate Limit ───────────────────────────────────────────
    flagged, blacklisted = analyze(clean)

    # ── IDS Rules ────────────────────────────────────────────
    enriched, threats = scan(flagged)

    # ── Persistência ─────────────────────────────────────────
    load_events(enriched)
    load_blacklist(blacklisted)
    load_quarantine(quarantined)
    load_threats(threats)

    # ── Alertas no terminal ───────────────────────────────────
    for entry in blacklisted:
        print(
            f"  {C.RED}[RATE_LIMIT CRITICAL]{C.RESET} "
            f"IP {C.BOLD}{entry['ip']}{C.RESET} bloqueado — {entry['reason']}"
        )

    for threat in threats:
        sev_color = C.RED if threat["severity"] == "HIGH" else C.YELLOW
        print(
            f"  {sev_color}[IDS {threat['severity']}]{C.RESET} "
            f"IP {C.BOLD}{threat['ip']}{C.RESET} | "
            f"Regra: {threat['rule']} | {threat['detail'][:60]}"
        )

    return {
        "total":       len(buffer),
        "clean":       len(clean),
        "quarantined": len(quarantined),
        "blacklisted": len(blacklisted),
        "threats":     len(threats),
    }


def watch() -> None:
    """
    Loop principal do daemon.
    Inicia monitoramento contínuo do arquivo de log.
    """
    init_db()

    print(f"\n{C.CYAN}{C.BOLD}  OLIMPO ENGINE — DAEMON V2{C.RESET}")
    print(f"  {C.DIM}Motor IDS + Rate Limit + ETL em tempo real{C.RESET}")
    print(f"  {C.DIM}Pressione Ctrl+C para encerrar.{C.RESET}\n")

    if not _wait_for_file(LOG_PATH):
        print(f"  {C.RED}ERRO:{C.RESET} Arquivo não encontrado após 30s.")
        print(f"  Execute primeiro: {C.BOLD}python tools/log_generator.py{C.RESET}\n")
        return

    print(f"  {C.GREEN}✔{C.RESET} Monitorando: {C.BOLD}{LOG_PATH}{C.RESET}\n")

    buffer: list[dict] = []
    last_flush = time.time()
    lines_read = 0
    batches    = 0

    with open(LOG_PATH, "r") as f:
        # Vai para o fim — não reprocessa histórico existente
        f.seek(0, 2)

        try:
            while True:
                line = f.readline()

                if line:
                    line = line.strip()
                    if line:
                        try:
                            event = json.loads(line)
                            buffer.append(event)
                            lines_read += 1
                        except json.JSONDecodeError:
                            pass  # linha malformada — ignora silenciosamente

                # Flush periódico do buffer
                now = time.time()
                if now - last_flush >= FLUSH_INTERVAL:
                    if buffer:
                        batches += 1
                        ts = datetime.utcnow().strftime("%H:%M:%S")
                        print(f"\n  {C.CYAN}[{ts}] Processando lote #{batches} "
                              f"({len(buffer)} eventos){C.RESET}")

                        result = _flush_buffer(buffer)
                        buffer.clear()

                        print(
                            f"  {C.DIM}→ Limpos: {result['clean']} | "
                            f"Quarentena: {result['quarantined']} | "
                            f"Bloqueios: {result['blacklisted']} | "
                            f"Ameaças IDS: {result['threats']}{C.RESET}"
                        )
                    last_flush = now

                else:
                    time.sleep(SLEEP_INTERVAL)

        except KeyboardInterrupt:
            # Processa o que sobrou no buffer antes de encerrar
            if buffer:
                print(f"\n  {C.YELLOW}Processando buffer final...{C.RESET}")
                _flush_buffer(buffer)

            print(
                f"\n  {C.GREEN}Daemon encerrado.{C.RESET} "
                f"Total lido: {lines_read} linhas | {batches} lotes.\n"
            )
