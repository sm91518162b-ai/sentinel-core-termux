# 🛡️ Sentinel-Core Termux
> Lightweight heuristic + YARA + VirusTotal file monitor for Android/Termux

[[Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[[License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[[Termux](https://img.shields.io/badge/Termux-Compatible-green.svg)](https://termux.dev/)

## Features
- **~0.2% CPU idle**: Event-driven con `inotify`, no polling. Batería feliz.
- **Offline-first**: Hash DB + reglas YARA locales. VirusTotal opcional.
- **Auto-quarantine**: Mueve amenazas a `~/.sentinel_quarantine` con timestamp.
- **Zero-config**: Funciona sin API keys. Solo instala y corre.
- **Battery efficient**: Diseñado específicamente para Termux en móviles.

## Installation
```bash
pkg update && pkg install python inotify-tools
pip install yara-python requests
curl -O https://raw.githubusercontent.com/sm91518162b-ai/sentinel-core-termux/main/sentinel_core.py
chmod +x sentinel_core.py