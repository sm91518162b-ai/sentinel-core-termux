#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sentinel-Core v1.1
Heuristic + Hash + YARA + VirusTotal file monitor for Termux/Linux
CPU: ~0.5% idle. VT solo si habilitas API key.
"""

import sys
import os
import hashlib
import time
import logging
import json
import requests
from pathlib import Path
from functools import lru_cache

try:
    import yara
except ImportError:
    yara = None
    print("[WARN] yara-python no instalado. pip install yara-python")

# -------------------------------------------------
# Configuración
# -------------------------------------------------
WATCH_PATHS = [
    str(Path.home()),
    "/sdcard/Download",
]

MALWARE_DB = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File",
}

QUARANTINE_DIR = Path.home() / ".sentinel_quarantine"
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = Path.home() / ".sentinel_core.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

MAX_HASH_SIZE = 50 * 1024 * 1024 # 50 MB

# -------------------------------------------------
# YARA Rules - Cárgalas desde archivo o ponlas inline
# -------------------------------------------------
YARA_RULES_PATH = Path.home() / "sentinel_rules.yar"
DEFAULT_YARA_RULES = """
rule Suspicious_Script_No_Shebang {
    meta:
        description = "Script ejecutable sin shebang"
        author = "Sentinel-Core"
    strings:
        $elf = { 7F 45 4C 46 }
        $mz = "MZ"
    condition:
        filesize < 10KB and not $elf and not $mz and uint16(0)!= 0x2321
}

rule EICAR_Test_File {
    meta:
        description = "Archivo de prueba EICAR"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Ransomware_Generic_Strings {
    meta:
        description = "Strings comunes de ransomware"
    strings:
        $s1 = "vssadmin delete shadows" nocase
        $s2 = "bcdedit /set {default} recoveryenabled No" nocase
        $s3 = ".encrypted" nocase
        $s4 = "YOUR FILES ARE ENCRYPTED" nocase
    condition:
        2 of them
}
"""

def load_yara_rules():
    """Carga reglas YARA. Si no existe el archivo, lo crea con reglas default."""
    if not yara:
        return None
    try:
        if not YARA_RULES_PATH.exists():
            YARA_RULES_PATH.write_text(DEFAULT_YARA_RULES)
            logging.info(f"Reglas YARA default creadas en {YARA_RULES_PATH}")
        return yara.compile(filepath=str(YARA_RULES_PATH))
    except Exception as e:
        logging.error(f"Error compilando YARA: {e}")
        return None

YARA_RULES = load_yara_rules()

# -------------------------------------------------
# VirusTotal - OPCIONAL. Requiere API key gratis de virustotal.com
# -------------------------------------------------
VT_API_KEY = "" # Pon tu API key aquí. Déjala vacía para desactivar VT.
VT_API_URL = "https://www.virustotal.com/api/v3/files/"
VT_CACHE = {} # Cache en memoria: hash -> resultado
VT_RATE_LIMIT = 4 # requests/min pa API gratis. 1 cada 15s.
last_vt_request = 0

def check_virustotal(file_hash: str) -> tuple[bool, str]:
    """
    Consulta hash en VirusTotal. Respeta rate limit.
    Devuelve (es_malicioso, detalle). Solo si VT_API_KEY está puesta.
    """
    global last_vt_request
    if not VT_API_KEY:
        return False, "VT desactivado"

    if file_hash in VT_CACHE:
        return VT_CACHE[file_hash]

    # Rate limit: 4/min
    elapsed = time.time() - last_vt_request
    if elapsed < 15:
        time.sleep(15 - elapsed)

    try:
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(VT_API_URL + file_hash, headers=headers, timeout=10)
        last_vt_request = time.time()

        if r.status_code == 200:
            data = r.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            total = sum(stats.values())
            if malicious >= 3: # 3+ motores lo marcan
                result = (True, f"VT: {malicious}/{total} motores")
                VT_CACHE[file_hash] = result
                return result
            else:
                result = (False, f"VT: {malicious}/{total} limpio")
                VT_CACHE[file_hash] = result
                return result
        elif r.status_code == 404:
            result = (False, "VT: Hash no conocido")
            VT_CACHE[file_hash] = result
            return result
        else:
            return False, f"VT: Error {r.status_code}"
    except Exception as e:
        return False, f"VT: Exception {e}"

# -------------------------------------------------
# Núcleo de detección
# -------------------------------------------------
@lru_cache(maxsize=2048)
def get_file_mtime_inode(path_str: str) -> tuple:
    try:
        st = os.stat(path_str)
        return st.st_mtime, st.st_ino
    except FileNotFoundError:
        return None

def sha256_full(file_path: Path) -> str:
    """Hash completo para VT. Solo se usa si archivo es sospechoso."""
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def run_yara_scan(p: Path) -> tuple[bool, str]:
    """Ejecuta reglas YARA si están disponibles."""
    if not YARA_RULES:
        return False, "YARA no disponible"
    try:
        matches = YARA_RULES.match(str(p), timeout=5)
        if matches:
            rules = ", ".join([m.rule for m in matches])
            return True, f"YARA: {rules}"
        return False, "YARA: Limpio"
    except Exception as e:
        return False, f"YARA: Error {e}"

def is_heuristic_suspicious(p: Path) -> bool:
    try:
        if not p.is_file():
            return False
        st = p.stat()
        if st.st_size < 10240 and os.access(p, os.X_OK):
            if p.suffix in {".sh", ".py", ".pl", ".php"}:
                with p.open("rb") as f:
                    if not f.read(2) == b'#!':
                        return True
            if not p.suffix and p.read_bytes().startswith(b'\x7fELF'):
                return True
        return False
    except:
        return False

def scan_file(p: Path) -> tuple[bool, str]:
    """
    Pipeline: Heurística -> Hash -> YARA -> VirusTotal
    Se detiene en cuanto algo da positivo para ahorrar CPU.
    """
    try:
        path_str = str(p)
        if get_file_mtime_inode(path_str) is None:
            return False, "No existe"

        # 1. Heurística rápida. Si no es sospechoso, ni seguimos.
        if not is_heuristic_suspicious(p):
            return False, "Descartado por heurística"

        # 2. Hash vs DB local - 0.001ms
        file_hash = sha256_full(p)
        if file_hash in MALWARE_DB:
            return True, f"Hash DB: {MALWARE_DB[file_hash]}"

        # 3. YARA - ~2ms. Offline, no gasta datos.
        yara_hit, yara_reason = run_yara_scan(p)
        if yara_hit:
            return True, yara_reason

        # 4. VirusTotal - Solo si hay API key y no pegó nada antes. Usa internet.
        vt_hit, vt_reason = check_virustotal(file_hash)
        if vt_hit:
            return True, vt_reason

        return False, "Limpio"
    except PermissionError:
        return False, "Sin permisos"
    except Exception as e:
        logging.error(f"Error escaneando {p}: {e}")
        return False, "Error"

def quarantine_file(p: Path, reason: str):
    try:
        dest = QUARANTINE_DIR / f"{int(time.time())}_{p.name}"
        p.rename(dest)
        msg = f"CUARENTENA: {p} -> {dest} | Razón: {reason}"
        print(msg)
        logging.warning(msg)
    except Exception as e:
        logging.error(f"Fallo al poner en cuarentena {p}: {e}")

# -------------------------------------------------
# Interfaz
# -------------------------------------------------
def process_file_event(file_str: str):
    p = Path(file_str).resolve()
    is_malware, reason = scan_file(p)
    if is_malware:
        quarantine_file(p, reason)
    else:
        logging.debug(f"OK: {p} | {reason}")

def main():
    if not yara:
        print("[INFO] Instala YARA: pip install yara-python")

    if len(sys.argv) == 3 and sys.argv[1] == "--single":
        process_file_event(sys.argv[2])
    elif len(sys.argv) == 2 and sys.argv[1] == "--daemon":
        print("Sentinel-Core v1.1 iniciado.")
        print("1. YARA rules:", YARA_RULES_PATH)
        print("2. VT API:", "Activado" if VT_API_KEY else "Desactivado")
        print(f'3. Comando monitor:')
        print(f'inotifywait -m -r -e create,modify --format "%w%f" {" ".join(WATCH_PATHS)} | xargs -I {{}} {sys.argv[0]} --single "{{}}"')
        sys.exit(0)
    else:
        print("Sentinel-Core v1.1")
        print("Uso:")
        print(f" {sys.argv[0]} --single /ruta/al/archivo")
        print(f" {sys.argv[0]} --daemon")
        sys.exit(1)

if __name__ == "__main__":
    main()