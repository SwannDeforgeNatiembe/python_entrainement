#!/usr/bin/env python3
# multi_tool.py
# Outil tout-en-un autonome (pas de dépendances externes)
# Python 3.8+

import os
import sys
import threading
import socket
import time
import sqlite3
import base64
import hashlib
import hmac
import secrets
import shutil
import stat
from datetime import datetime
from pathlib import Path
from typing import Optional

# ---------------------------
# Petit logger
# ---------------------------
def log(msg: str):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

# ---------------------------
# Crypto léger (PBKDF2 + HMAC-based stream XOR)
# - dérive une clé avec PBKDF2-HMAC-SHA256
# - génère un keystream HMAC-SHA256(counter || nonce)
# - XOR avec les données
# ---------------------------
def derive_key(password: str, salt: bytes, iterations: int = 200_000, dklen: int = 32) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen)

def stream_xor(data: bytes, key: bytes, nonce: bytes) -> bytes:
    out = bytearray(len(data))
    block = 0
    pos = 0
    while pos < len(data):
        counter = block.to_bytes(8, 'big')
        h = hmac.new(key, counter + nonce, 'sha256').digest()
        chunk = data[pos:pos+len(h)]
        for i, b in enumerate(chunk):
            out[pos + i] = b ^ h[i]
        pos += len(chunk)
        block += 1
    return bytes(out)

def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    key = derive_key(password, salt)
    ciphertext = stream_xor(plaintext, key, nonce)
    # format: salt||nonce||ciphertext, base64 for storage
    return base64.b64encode(salt + nonce + ciphertext)

def decrypt_bytes(payload_b64: bytes, password: str) -> Optional[bytes]:
    try:
        raw = base64.b64decode(payload_b64)
        if len(raw) < 32:
            return None
        salt = raw[:16]
        nonce = raw[16:32]
        ciphertext = raw[32:]
        key = derive_key(password, salt)
        plaintext = stream_xor(ciphertext, key, nonce)
        return plaintext
    except Exception:
        return None

# ---------------------------
# Base de données (notes chiffrées)
# ---------------------------
DB_PATH = Path.home() / ".multi_tool_notes.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            content BLOB,
            created_at TEXT
        )
    ''')
    conn.commit()
    conn.close()

def store_note(title: str, content_bytes: bytes, password: str):
    encrypted = encrypt_bytes(content_bytes, password)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('INSERT INTO notes (title, content, created_at) VALUES (?, ?, ?)',
                (title, encrypted, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    log(f"Note '{title}' stockée (chiffrée).")

def list_notes():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT id, title, created_at FROM notes ORDER BY created_at DESC')
    rows = cur.fetchall()
    conn.close()
    return rows

def get_note_raw(note_id: int):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT id, title, content, created_at FROM notes WHERE id = ?', (note_id,))
    row = cur.fetchone()
    conn.close()
    return row

def delete_note(note_id: int):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('DELETE FROM notes WHERE id = ?', (note_id,))
    conn.commit()
    conn.close()
    log(f"Note id={note_id} supprimée.")

# ---------------------------
# Outils fichier
# ---------------------------
def list_dir(path: str):
    p = Path(path).expanduser().resolve()
    if not p.exists():
        print("Chemin introuvable.")
        return
    for child in sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
        try:
            mode = 'd' if child.is_dir() else '-'
            perms = stat.filemode(child.stat().st_mode)
            size = child.stat().st_size
            mtime = datetime.fromtimestamp(child.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            print(f"{mode}{perms} {size:8d} {mtime}  {child.name}")
        except PermissionError:
            print(f"?---------    ???      {child.name}")

def view_file(path: str, max_bytes: int = 1024 * 1024):
    p = Path(path).expanduser()
    if not p.exists():
        print("Fichier introuvable.")
        return
    try:
        with p.open('rb') as f:
            data = f.read(max_bytes)
            try:
                text = data.decode('utf-8')
                print(text)
            except UnicodeDecodeError:
                print("Fichier binaire — affichage hex (par bloc 16 bytes) :")
                hexdump(data)
    except Exception as e:
        print("Erreur:", e)

def hexdump(data: bytes, width: int = 16):
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hexpart = ' '.join(f"{b:02x}" for b in chunk)
        asc = ''.join((chr(b) if 32 <= b < 127 else '.') for b in chunk)
        print(f"{i:08x}  {hexpart:<{width*3}}  {asc}")

def copy_file(src: str, dst: str):
    try:
        shutil.copy2(src, dst)
        log(f"Copié {src} -> {dst}")
    except Exception as e:
        print("Erreur:", e)

# ---------------------------
# Serveur HTTP très simple (file server)
# ---------------------------
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

class AuthHandler(SimpleHTTPRequestHandler):
    # Optionnel : basic auth support (username:password)
    AUTH = None  # set to "username:password" if needed (base64 no, we will compare raw)

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="multi_tool"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        if AuthHandler.AUTH:
            auth = self.headers.get('Authorization')
            if not auth or not auth.startswith('Basic '):
                self.do_AUTHHEAD()
                self.wfile.write(b'Authentication required.')
                return
            import base64
            user_pass = base64.b64decode(auth.split(' ',1)[1]).decode('utf-8')
            if user_pass != AuthHandler.AUTH:
                self.do_AUTHHEAD()
                self.wfile.write(b'Forbidden.')
                return
        super().do_GET()

def start_http_server(directory: str = '.', port: int = 8000, auth: Optional[str] = None):
    os.chdir(directory)
    log(f"Demarrage server HTTP sur 0.0.0.0:{port}, racine: {os.getcwd()}")
    if auth:
        AuthHandler.AUTH = auth
        log("Authentification Basic activée.")
    server = ThreadingHTTPServer(('', port), AuthHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
        log("Server HTTP arrêté.")

# ---------------------------
# Scanner de ports (connect)
# ---------------------------
def scan_ports(host: str, ports: list, timeout: float = 0.5, threads: int = 100):
    q = ports.copy()
    q_lock = threading.Lock()
    results = []
    def worker():
        while True:
            with q_lock:
                if not q:
                    return
                port = q.pop()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                err = s.connect_ex((host, port))
                s.close()
                if err == 0:
                    results.append((port, 'open'))
                    print(f"{port}/tcp open")
            except Exception:
                pass
    thread_list = []
    for _ in range(min(threads, len(ports))):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        thread_list.append(t)
    for t in thread_list:
        t.join()
    return sorted(results)

# ---------------------------
# Utilitaires
# ---------------------------
def gen_password(length: int = 16, use_symbols: bool = True) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.<>?"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def encode_base64(s: str) -> str:
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')

def decode_base64(s: str) -> str:
    return base64.b64decode(s.encode('utf-8')).decode('utf-8')

def encode_hex(s: bytes) -> str:
    return s.hex()

def decode_hex(s: str) -> bytes:
    return bytes.fromhex(s)

def system_info():
    import platform
    info = {
        'platform': platform.platform(),
        'machine': platform.machine(),
        'python': sys.version.replace('\n',' '),
        'cwd': os.getcwd(),
        'user': os.getlogin() if hasattr(os, 'getlogin') else os.environ.get('USER','?')
    }
    for k,v in info.items():
        print(f"{k:8s}: {v}")

# ---------------------------
# Interface textuelle (menu)
# ---------------------------
MENU = """
=== Multi-Tool (autonome) ===
Choisis une option:
 1) Explorateur: lister un dossier
 2) Visualiser fichier / hexdump
 3) Copier fichier
 4) Serveur HTTP simple (fichier) [bloquant]
 5) Scanner de ports (TCP connect)
 6) Gestionnaire de notes chiffrées (store/list/view/delete)
 7) Générateur de mot de passe
 8) Encode/decode Base64 / Hex
 9) Info système
 0) Quitter
"""

def menu_loop():
    init_db()
    while True:
        print(MENU)
        try:
            choice = input("Choix> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            log("Bye.")
            return
        if choice == '1':
            p = input("Chemin (.)> ").strip() or "."
            list_dir(p)
        elif choice == '2':
            p = input("Fichier> ").strip()
            view_file(p)
        elif choice == '3':
            src = input("Source> ").strip()
            dst = input("Destination> ").strip()
            copy_file(src, dst)
        elif choice == '4':
            d = input("Répertoire à partager (.)> ").strip() or "."
            port = int(input("Port (8000)> ").strip() or "8000")
            authraw = input("Si Basic auth voulu, entre 'user:pass' sinon laisse vide> ").strip()
            try:
                start_http_server(d, port, authraw or None)
            except Exception as e:
                print("Erreur serveur:", e)
        elif choice == '5':
            host = input("Hôte (ip/domain) > ").strip()
            prange = input("Ports (ex: 22,80,443 or 1-1024) > ").strip()
            ports = []
            for part in prange.split(','):
                part = part.strip()
                if '-' in part:
                    a,b = part.split('-',1)
                    ports += list(range(int(a), int(b)+1))
                else:
                    if part:
                        ports.append(int(part))
            t0 = time.time()
            res = scan_ports(host, ports)
            t1 = time.time()
            log(f"Scan terminé en {t1-t0:.2f}s — {len(res)} ports ouverts trouvés.")
        elif choice == '6':
            print("Notes: 1 store  2 list  3 view  4 delete  0 back")
            sub = input(">> ").strip()
            if sub == '1':
                title = input("Titre> ").strip()
                print("Tape ta note (EOF pour finir) :")
                try:
                    txt = sys.stdin.read()
                except Exception:
                    txt = input("Note> ")
                pwd = input("Mot de passe pour chiffrer la note> ").strip()
                store_note(title, txt.encode('utf-8'), pwd)
            elif sub == '2':
                rows = list_notes()
                for r in rows:
                    print(f"{r[0]:3d}  {r[1]:30.30s}  {r[2]}")
            elif sub == '3':
                nid = int(input("ID note> ").strip())
                row = get_note_raw(nid)
                if not row:
                    print("Introuvable.")
                else:
                    pwd = input("Mot de passe pour déchiffrer> ").strip()
                    plaintext = decrypt_bytes(row[2], pwd)
                    if plaintext is None:
                        print("*** Echec de déchiffrement ou mot de passe incorrect.")
                    else:
                        print(f"--- {row[1]} ---")
                        try:
                            print(plaintext.decode('utf-8'))
                        except Exception:
                            print(plaintext)
            elif sub == '4':
                nid = int(input("ID note à supprimer> ").strip())
                delete_note(nid)
            else:
                continue
        elif choice == '7':
            l = int(input("Longueur (16)> ").strip() or "16")
            use_symbols = input("Symboles? (Y/n) > ").strip().lower() != 'n'
            print("Mot de passe généré:", gen_password(l, use_symbols))
        elif choice == '8':
            print("a) enc64 b) dec64 c) enchex d) dechex")
            op = input("choix> ").strip().lower()
            if op == 'a':
                s = input("Texte> ")
                print(encode_base64(s))
            elif op == 'b':
                s = input("B64> ")
                try:
                    print(decode_base64(s))
                except Exception as e:
                    print("Erreur:", e)
            elif op == 'c':
                s = input("Texte> ")
                print(encode_hex(s.encode('utf-8')))
            elif op == 'd':
                s = input("Hex> ")
                try:
                    print(decode_hex(s))
                except Exception as e:
                    print("Erreur:", e)
        elif choice == '9':
            system_info()
        elif choice == '0':
            log("Bye.")
            return
        else:
            print("Choix invalide.")

if __name__ == '__main__':
    try:
        menu_loop()
    except Exception as e:
        print("Erreur fatale:", e)
        raise
