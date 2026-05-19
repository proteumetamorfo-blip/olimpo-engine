#!/usr/bin/env python3
"""
tools/report_exporter.py
────────────────────────
Evolução 5 — Exportação de Relatório HTML.

Gera um arquivo HTML auto-contido com visual dark/gold
(consistente com o Olimpo Digital) mostrando os resultados
da análise de segurança.

Abrível no navegador do celular ou do PC.
Colocável no GitHub Pages como demonstração visual do projeto.

Uso:
  python tools/report_exporter.py
  python tools/report_exporter.py --output meu_relatorio.html
"""

import os
import sys
import argparse
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.loader import init_db, live_stats

OUT_DEFAULT = os.path.join(
    os.path.dirname(__file__), "..", "logs", "relatorio_seguranca.html"
)


def _badge(level: str) -> str:
    styles = {
        "CRITICAL": "background:#8b1a1a;color:#f0ece4",
        "WARNING":  "background:#7a6000;color:#f0ece4",
        "OK":       "background:#1a4a1a;color:#c8f0c8",
        "HIGH":     "background:#8b1a1a;color:#f0ece4",
        "MEDIUM":   "background:#7a6000;color:#f0ece4",
    }
    style = styles.get(level, "background:#333;color:#ccc")
    return f'<span style="padding:2px 8px;border-radius:3px;font-size:0.75rem;font-family:monospace;{style}">{level}</span>'


def _row(*cells, header: bool = False) -> str:
    tag = "th" if header else "td"
    inner = "".join(f"<{tag}>{c}</{tag}>" for c in cells)
    return f"<tr>{inner}</tr>"


def build_html(stats: dict) -> str:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    total = stats["total"] or 1

    ok_pct   = round(((stats["total"] - stats["warning"] - stats["critical"]) / total) * 100)
    warn_pct = round((stats["warning"]  / total) * 100)
    crit_pct = round((stats["critical"] / total) * 100)

    # ── Tabela de eventos recentes ─────────────────────────
    events_rows = "\n".join(
        _row(
            ev["ip"], ev["event"], ev["route"],
            _badge(ev["alert_level"]),
            f'<span style="color:#c9a84c;font-size:0.75rem">{ev["ids_tags"] or "—"}</span>',
            f'<span style="color:#666;font-size:0.75rem">{ev["timestamp"]}</span>',
        )
        for ev in stats["recent_events"]
    )

    # ── Tabela de blacklist ────────────────────────────────
    bl_rows = "\n".join(
        _row(
            f'<strong style="color:#ff6b6b">{bl["ip"]}</strong>',
            bl["event_type"],
            f'<span style="color:#c9a84c">{bl["count"]}x</span>',
            bl["reason"],
            f'<span style="color:#666;font-size:0.75rem">{bl["detected_at"]}</span>',
        )
        for bl in stats["blacklist"]
    ) or "<tr><td colspan='5' style='color:#666;text-align:center'>Nenhum IP bloqueado</td></tr>"

    # ── Tabela de ameaças IDS ─────────────────────────────
    thr_rows = "\n".join(
        _row(
            f'<strong style="color:#ff6b6b">{t["ip"]}</strong>',
            f'<span style="color:#c9a84c;font-family:monospace">{t["rule"]}</span>',
            _badge(t["severity"]),
            f'<span style="font-size:0.8rem">{t["detail"]}</span>',
            f'<span style="color:#666;font-size:0.75rem">{t["detected_at"]}</span>',
        )
        for t in stats["recent_threats"]
    ) or "<tr><td colspan='5' style='color:#666;text-align:center'>Nenhuma ameaça IDS detectada</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>Olimpo Engine — Relatório de Segurança</title>
  <style>
    :root {{
      --obsidian: #0a0908; --gold: #c9a84c; --gold-dim: #8a6f2e;
      --marble: #f0ece4;   --ember: #8b1a1a; --mid: #1a1714;
    }}
    * {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{
      background:var(--obsidian); color:var(--marble);
      font-family:'Segoe UI',system-ui,sans-serif;
      font-size:14px; line-height:1.6; padding:1.5rem;
    }}
    h1 {{ font-family:Georgia,serif; color:var(--gold); font-size:clamp(1.4rem,4vw,2rem); letter-spacing:0.05em; }}
    h2 {{ font-family:Georgia,serif; color:var(--gold); font-size:1.1rem; margin-bottom:1rem; letter-spacing:0.08em; }}
    .subtitle {{ color:rgba(240,236,228,0.45); font-size:0.85rem; margin-top:0.35rem; font-style:italic; }}
    header {{ border-bottom:1px solid rgba(201,168,76,0.25); padding-bottom:1.25rem; margin-bottom:1.75rem; }}
    .meta {{ font-family:monospace; font-size:0.7rem; color:rgba(201,168,76,0.5); margin-top:0.5rem; }}

    /* Stats grid */
    .stats-grid {{
      display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr));
      gap:0.75rem; margin-bottom:2rem;
    }}
    .stat-card {{
      background:var(--mid); border:1px solid rgba(201,168,76,0.2);
      border-radius:4px; padding:1rem; text-align:center;
    }}
    .stat-num {{ font-size:2rem; font-weight:700; color:var(--gold); line-height:1; }}
    .stat-num.red {{ color:#ff6b6b; }}
    .stat-num.yellow {{ color:#ffd166; }}
    .stat-num.purple {{ color:#c084fc; }}
    .stat-label {{ font-size:0.65rem; letter-spacing:0.12em; color:rgba(240,236,228,0.4); margin-top:0.3rem; text-transform:uppercase; }}

    /* Progress bars */
    .dist-section {{ margin-bottom:2rem; }}
    .dist-row {{ display:flex; align-items:center; gap:0.75rem; margin-bottom:0.6rem; }}
    .dist-label {{ width:70px; font-size:0.72rem; font-family:monospace; color:rgba(240,236,228,0.5); }}
    .bar-track {{ flex:1; height:8px; background:rgba(255,255,255,0.06); border-radius:4px; overflow:hidden; }}
    .bar-fill {{ height:100%; border-radius:4px; transition:width 0.3s; }}
    .bar-ok {{ background:linear-gradient(90deg,#1a6b1a,#4caf50); }}
    .bar-warn {{ background:linear-gradient(90deg,#7a6000,#ffd166); }}
    .bar-crit {{ background:linear-gradient(90deg,#6b1a1a,#ff6b6b); }}
    .dist-val {{ width:40px; text-align:right; font-family:monospace; font-size:0.72rem; color:rgba(240,236,228,0.5); }}

    /* Tables */
    .table-section {{ margin-bottom:2rem; }}
    table {{ width:100%; border-collapse:collapse; font-size:0.82rem; }}
    th {{
      background:rgba(201,168,76,0.12); color:var(--gold);
      font-family:monospace; font-size:0.65rem; letter-spacing:0.1em;
      text-transform:uppercase; padding:0.6rem 0.75rem; text-align:left;
      border-bottom:1px solid rgba(201,168,76,0.2);
    }}
    td {{ padding:0.55rem 0.75rem; border-bottom:1px solid rgba(255,255,255,0.04); }}
    tr:hover td {{ background:rgba(201,168,76,0.04); }}
    .card {{ background:var(--mid); border:1px solid rgba(201,168,76,0.18); border-radius:4px; padding:1.25rem; }}
    footer {{
      margin-top:2.5rem; padding-top:1rem;
      border-top:1px solid rgba(201,168,76,0.15);
      text-align:center; font-family:monospace;
      font-size:0.65rem; color:rgba(201,168,76,0.3);
    }}
    @media(max-width:600px) {{ body {{ padding:0.75rem; }} td,th {{ padding:0.4rem 0.5rem; }} }}
  </style>
</head>
<body>

<header>
  <h1>⚡ OLIMPO ENGINE</h1>
  <p class="subtitle">Relatório de Auditoria de Segurança — Business Intelligence Automation Backend</p>
  <p class="meta">Gerado em: {now} | Por: Vinícios Silva</p>
</header>

<!-- Contadores -->
<section class="stats-grid">
  <div class="stat-card">
    <div class="stat-num">{stats['total']}</div>
    <div class="stat-label">Total Eventos</div>
  </div>
  <div class="stat-card">
    <div class="stat-num red">{stats['critical']}</div>
    <div class="stat-label">Critical</div>
  </div>
  <div class="stat-card">
    <div class="stat-num yellow">{stats['warning']}</div>
    <div class="stat-label">Warning</div>
  </div>
  <div class="stat-card">
    <div class="stat-num purple">{stats['threats']}</div>
    <div class="stat-label">Ameaças IDS</div>
  </div>
  <div class="stat-card">
    <div class="stat-num red">{stats['blacklisted']}</div>
    <div class="stat-label">Blacklist</div>
  </div>
  <div class="stat-card">
    <div class="stat-num yellow">{stats['quarantined']}</div>
    <div class="stat-label">Quarentena</div>
  </div>
</section>

<!-- Distribuição -->
<section class="dist-section card" style="margin-bottom:2rem">
  <h2>DISTRIBUIÇÃO DE ALERTAS</h2>
  <div class="dist-row">
    <span class="dist-label">OK</span>
    <div class="bar-track"><div class="bar-fill bar-ok" style="width:{ok_pct}%"></div></div>
    <span class="dist-val">{ok_pct}%</span>
  </div>
  <div class="dist-row">
    <span class="dist-label">WARNING</span>
    <div class="bar-track"><div class="bar-fill bar-warn" style="width:{warn_pct}%"></div></div>
    <span class="dist-val">{warn_pct}%</span>
  </div>
  <div class="dist-row">
    <span class="dist-label">CRITICAL</span>
    <div class="bar-track"><div class="bar-fill bar-crit" style="width:{crit_pct}%"></div></div>
    <span class="dist-val">{crit_pct}%</span>
  </div>
</section>

<!-- Blacklist -->
<section class="table-section card">
  <h2>🚫 BLACKLIST — IPs BLOQUEADOS</h2>
  <table>
    <thead><tr>{''.join(f'<th>{h}</th>' for h in ['IP','Evento','Contagem','Motivo','Detectado'])}</tr></thead>
    <tbody>{bl_rows}</tbody>
  </table>
</section>

<!-- Ameaças IDS -->
<section class="table-section card" style="margin-top:1rem">
  <h2>◉ AMEAÇAS IDS DETECTADAS</h2>
  <table>
    <thead><tr>{''.join(f'<th>{h}</th>' for h in ['IP','Regra','Severidade','Detalhe','Detectado'])}</tr></thead>
    <tbody>{thr_rows}</tbody>
  </table>
</section>

<!-- Eventos recentes -->
<section class="table-section card" style="margin-top:1rem">
  <h2>📋 ÚLTIMOS EVENTOS PROCESSADOS</h2>
  <table>
    <thead><tr>{''.join(f'<th>{h}</th>' for h in ['IP','Evento','Rota','Alerta','IDS Tags','Timestamp'])}</tr></thead>
    <tbody>{events_rows}</tbody>
  </table>
</section>

<footer>
  OLIMPO ENGINE V2 · Business Intelligence Automation Backend · Vinícios Silva · Goiana, PE
</footer>

</body>
</html>"""


def export(output_path: str = OUT_DEFAULT) -> None:
    init_db()
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    stats = live_stats()
    html  = build_html(stats)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n  ✔ Relatório gerado: {output_path}")
    print(f"  Abra no navegador para visualizar.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Olimpo Engine — Exportador HTML")
    parser.add_argument("--output", default=OUT_DEFAULT, help="Caminho do arquivo de saída")
    args = parser.parse_args()
    export(args.output)
