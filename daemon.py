#!/usr/bin/env python3
"""
daemon.py
─────────
Ponto de entrada do modo daemon (Evolução 1).

Uso no Termux:
  # Terminal 1 — gera os logs
  python tools/log_generator.py --speed fast

  # Terminal 2 — daemon monitora e processa
  python daemon.py

  # Terminal 3 — dashboard ao vivo (opcional)
  python dashboard.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.watcher import watch

if __name__ == "__main__":
    watch()
