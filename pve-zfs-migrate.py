#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import sys
import re
import os
import time
import shutil
import math # Für Größenumrechnung
import argparse # Für Kommandozeilenargumente
from collections import defaultdict

# --- Konfiguration ---
# Diese Werte werden als Standardwerte für die Kommandozeilenargumente verwendet
# und können über diese überschrieben werden.
DEFAULT_SSH_USER = "root"
# Beispiel: Wenn dein Pool 'tank' heißt und Daten unter 'tank/data' liegen
DEFAULT_REMOTE_POOL_BASE = "rpool/data" # Basis-Pfad auf dem Quell-PVE
DEFAULT_LOCAL_POOL_BASE = DEFAULT_REMOTE_POOL_BASE # Basis-Pfad auf dem Ziel-PVE (dieses System)
PVE_QEMU_CONF_DIR = "/etc/pve/qemu-server" # Standard-PVE-Pfad für VM-Konfigs
PVE_LXC_CONF_DIR = "/etc/pve/lxc"         # Standard-PVE-Pfad für LXC-Konfigs
# --- Ende Konfiguration ---

# --- Color Definitions ---
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"

# --- Farbige Ausgabe Helper ---
def print_info(msg):
    print(f"{COLOR_CYAN}{msg}{COLOR_RESET}")

def print_success(msg):
    print(f"{COLOR_GREEN}{msg}{COLOR_RESET}")

def print_warning(msg):
    print(f"{COLOR_YELLOW}{msg}{COLOR_RESET}", file=sys.stderr)

def print_error(msg):
    print(f"{COLOR_RED}{msg}{COLOR_RESET}", file=sys.stderr)

def prompt_user(msg):
    """Stellt eine Benutzerfrage (nur im interaktiven Modus relevant)."""
    return input(f"{COLOR_MAGENTA}{msg} {COLOR_RESET}")

# --- Hilfsfunktion zur Umwandlung von Bytes in lesbare Formate ---
def bytes_to_human_readable(num_bytes):
    if num_bytes is None or num_bytes < 0:
        return "N/A"
    if num_bytes == 0:
        return "0 Bytes"

    power = 1024
    n = 0
    power_labels = {0 : ' Bytes', 1: ' KiB', 2: ' MiB', 3: ' GiB', 4: ' TiB'}
    while num_bytes >= power and n < len(power_labels) - 1:
        num_bytes /= power
        n += 1
    if n == 0:
        return f"{num_bytes:.0f}{power_labels[n]}"
    elif num_bytes < 10:
         return f"{num_bytes:.2f}{power_labels[n]}"
    else:
         return f"{num_bytes:.1f}{power_labels[n]}"

# --- Hilfsfunktion zur Konvertierung von Größenangaben in Bytes ---
def size_to_bytes(size_str):
    if not size_str: return None
    size_str = size_str.strip().upper()
    multipliers = {'K': 1024, 'M': 1024**2, 'G': 1024**3, 'T': 1024**4, 'P': 1024**5}
    num_part = size_str
    unit = None

    for suffix in multipliers:
        if size_str.endswith(suffix):
            unit = suffix
            num_part = size_str[:-len(suffix)].strip()
            break
    try:
        num = float(num_part)
        if unit:
            num *= multipliers[unit]
        return int(math.ceil(num))
    except ValueError:
        print_warning(f"   (Warnung: Konnte Größenangabe '{size_str}' nicht in Bytes umwandeln)")
        return None

# --- Hilfsfunktionen für Befehlsausführung ---
def run_command(cmd_list, check=True, capture_output=False, text=True):
    """Führt einen lokalen Befehl aus."""
    print_info(f"[*] Führe lokal aus: {' '.join(cmd_list)}")
    try:
        result = subprocess.run(
            cmd_list,
            check=check,
            capture_output=capture_output,
            text=text,
            errors='replace'
        )
        return result
    except FileNotFoundError:
        print_error(f"[!] Fehler: Befehl '{cmd_list[0]}' nicht gefunden. Ist er im PATH?")
        if check: sys.exit(1)
        return None
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip() if e.stderr else "(Keine stderr Ausgabe erfasst)"
        print_error(f"[!] Lokaler Befehl fehlgeschlagen (Code {e.returncode}): {' '.join(cmd_list)}")
        print_error(f"    Fehler: {stderr_output}")
        # sys.exit wird durch check=True ausgelöst
        return None
    except Exception as e:
        print_error(f"[!] Unerwarteter Fehler beim Ausführen von {' '.join(cmd_list)}: {e}")
        if check: sys.exit(1)
        return None

def run_remote_command(host, user, cmd, check=True, quiet=False):
    """Führt einen Befehl auf dem entfernten Host via SSH aus."""
    remote_shell_cmd = ["bash", "-s"]
    ssh_cmd = ["ssh",
               "-o", "BatchMode=yes", # Wichtig für nicht-interaktive Ausführung
               "-o", "ConnectTimeout=10",
               f"{user}@{host}",
               "--"] + remote_shell_cmd

    if not quiet:
        print_info(f"[*] Führe auf {host} via 'bash -s' (stdin) aus: {cmd}")
    try:
        result = subprocess.run(
            ssh_cmd,
            input=cmd,
            check=check,
            capture_output=True,
            text=True,
            errors='replace',
            # Kein Timeout hier, da der *Remote-Befehl* lange dauern kann. ConnectTimeout oben ist für die Verbindung.
        )
        return result.stdout.strip()

    except FileNotFoundError:
        print_error("[!] Fehler: Befehl 'ssh' nicht gefunden. Ist er im PATH?")
        if check: sys.exit(1)
        return None
    # TimeoutExpired ist hier weniger wahrscheinlich, da wir keinen Timeout in subprocess.run setzen
    # except subprocess.TimeoutExpired as e: ... (kann bei Bedarf hinzugefügt werden)

    except subprocess.CalledProcessError as e:
        if not quiet:
            print_error(f"[!] SSH/'bash -s'-Befehl fehlgeschlagen (Code {e.returncode}): {' '.join(e.cmd)}")
            input_cmd_display = cmd
            try:
                if e.input: input_cmd_display = e.input.strip()
            except: pass
            print_error(f"    Befehl (via stdin): {input_cmd_display}")
            stderr_msg = e.stderr.strip() if e.stderr else "(Keine stderr Ausgabe)"
            print_error(f"    Fehler: {stderr_msg}")

            # --- BEGINN DER ÄNDERUNG ---
            if "Permission denied" in stderr_msg or "publickey" in stderr_msg:
                print_warning("    -> SSH-Authentifizierungsproblem (Passwort/Schlüssel?) erkannt.")
                try:
                    # Frage den Benutzer, ob ssh-copy-id ausgeführt werden soll
                    user_input = prompt_user(f"[?] Soll versucht werden, den SSH-Schlüssel mit 'ssh-copy-id {user}@{host}' zu kopieren? (j/N): ").strip().lower()
                    if user_input == 'j':
                        print_info(f"[*] Versuche 'ssh-copy-id' für {user}@{host} auszuführen...")
                        ssh_copy_cmd = ["ssh-copy-id", f"{user}@{host}"]
                        # Führe ssh-copy-id lokal aus. check=False, da ssh-copy-id selbst fehlschlagen kann.
                        copy_result = run_command(ssh_copy_cmd, check=False, capture_output=True)

                        if copy_result is not None and copy_result.returncode == 0:
                            print_success(f"[+] 'ssh-copy-id' für {user}@{host} wurde scheinbar erfolgreich ausgeführt.")
                            print_warning("[!] Bitte versuchen Sie, das Skript erneut auszuführen.")
                        else:
                            print_error(f"[!] 'ssh-copy-id' für {user}@{host} ist fehlgeschlagen oder wurde abgebrochen.")
                            if copy_result and copy_result.stderr:
                                print_error(f"    Fehler von ssh-copy-id: {copy_result.stderr.strip()}")
                            elif copy_result and copy_result.stdout: # Manchmal landet die Fehlermeldung auch in stdout
                                print_error(f"    Ausgabe von ssh-copy-id: {copy_result.stdout.strip()}")
                            print_warning("[!] Bitte überprüfen Sie die SSH-Konfiguration manuell und versuchen Sie es erneut.")
                        # Nach dem Versuch (erfolgreich oder nicht), beenden wir das Skript.
                        # Der Benutzer muss es neu starten, um die geänderte Konfiguration zu nutzen.
                        sys.exit(1) # Beende mit Fehlercode, da der ursprüngliche Befehl fehlschlug
                    else:
                        print_info("[*] 'ssh-copy-id' wird nicht ausgeführt.")
                        # Fahre mit der normalen Fehlerbehandlung fort (führt zu sys.exit, wenn check=True)

                except Exception as inner_e:
                    print_error(f"[!] Unerwarteter Fehler während der ssh-copy-id Interaktion: {inner_e}")
                    # Fahre mit der normalen Fehlerbehandlung fort

            # --- ENDE DER ÄNDERUNG ---

            elif "Could not resolve hostname" in stderr_msg:
                print_warning("    -> Hostname konnte nicht aufgelöst werden. Überprüfe Namen/IP und Netzwerk.")
            elif "connect to host" in stderr_msg and "port 22" in stderr_msg:
                 print_warning("    -> Verbindung zu Port 22 fehlgeschlagen. Läuft SSHD auf dem Host? Firewall?")
            else:
                print_warning("    -> Der Befehl auf dem Remote-Host (innerhalb von 'bash -s') ist fehlgeschlagen oder ein anderes SSH-Problem.")

        if check: # Wird nur erreicht, wenn ssh-copy-id nicht ausgeführt wurde oder fehlschlug
            sys.exit("Remote-Kommando fehlgeschlagen.") # Beende das Skript
        return None # Wird nur erreicht, wenn check=False ist
    except Exception as e:
        print_error(f"[!] Unerwarteter Fehler beim Ausführen von {' '.join(ssh_cmd)} mit Input '{cmd}': {e}")
        if check and not quiet:
            sys.exit(1)
        return None

# --- Funktion zum Schätzen der Snapshot-Größe ---
def get_remote_snapshot_size(host, user, snapshot_full_name, incremental_source_full_name=None):
    """Schätzt die Größe eines ZFS-Send-Streams auf dem Remote-Host."""
    if incremental_source_full_name:
        cmd = f"zfs send -nvP -i '{incremental_source_full_name}' '{snapshot_full_name}'"
    else:
        cmd = f"zfs send -nvP '{snapshot_full_name}'"

    output = run_remote_command(host, user, cmd, check=False, quiet=True)

    if output is None:
        return None # Fehler wurde bereits in run_remote_command geloggt

    size_pattern = re.compile(
        r"(?:total estimated size is\s+([\d.]+[KMGTP]?))|(?:^size\s+(\d+)$)",
        re.IGNORECASE | re.MULTILINE
    )
    estimated_size_bytes = None
    match = size_pattern.search(output)

    if match:
        if match.group(1): # Format "total estimated size is ..."
            size_str_human = match.group(1)
            estimated_size_bytes = size_to_bytes(size_str_human)
        elif match.group(2): # Format "size ..."
            size_str_bytes = match.group(2)
            try:
                estimated_size_bytes = int(size_str_bytes)
            except ValueError:
                estimated_size_bytes = None

    return estimated_size_bytes

# --- Funktion zum Holen des Gast-Namens ---
def get_guest_name(host, user, guest_id, guest_type):
    """Holt den Namen einer VM oder eines LXC."""
    config_file = ""
    grep_pattern = ""
    api_cmd_base = ""

    if guest_type == "VM":
        config_file = f"{PVE_QEMU_CONF_DIR}/{guest_id}.conf"
        grep_pattern = '^(name|hostname):'
        api_cmd_base = "qm"
    elif guest_type == "LXC":
        config_file = f"{PVE_LXC_CONF_DIR}/{guest_id}.conf"
        grep_pattern = '^hostname:'
        api_cmd_base = "pct"
    else:
        print_warning(f"   (Warnung: Unbekannter Gast-Typ '{guest_type}' für ID {guest_id})")
        return "(Unbekannter Typ)"

    # 1. Versuch: Konfigurationsdatei
    cmd = f"if test -f {config_file}; then grep -m 1 -E '{grep_pattern}' {config_file} | cut -d ':' -f 2-; fi"
    name_output = run_remote_command(host, user, cmd, check=False, quiet=True)

    if name_output and name_output.strip():
        return name_output.strip()
    else:
        # 2. Versuch: PVE API
        config_cmd = f"{api_cmd_base} config {guest_id} --current | grep -m 1 -E '{grep_pattern}' | cut -d ':' -f 2-"
        name_output_api = run_remote_command(host, user, config_cmd, check=False, quiet=True)

        if name_output_api and name_output_api.strip():
            return name_output_api.strip()
        else:
            print_warning(f"   (Warnung: Name für {guest_type} {guest_id} konnte weder aus Datei noch via API ermittelt werden)")
            return "(Name nicht gefunden)"

# --- Funktion zum Holen und Gruppieren der Gast-Snapshots ---
def get_grouped_guests(host, user, remote_pool_base):
    """Holt Snapshots, sortiert und gruppiert nach Gast."""
    print_info(f"[*] Suche nach allen Snapshots unter '{remote_pool_base}' auf {host}...")
    cmd = f"zfs list -t snapshot -o name,creation -s creation -r -p -H '{remote_pool_base}'"
    output = run_remote_command(host, user, cmd, check=True)

    if not output:
        print_info(f"[*] Keine Snapshots unter '{remote_pool_base}' auf {host} gefunden.")
        return {}

    all_snapshots_by_dataset = defaultdict(list)
    snapshot_pattern = re.compile(r'^(.*?)@(.*)$')

    print_info("[*] Analysiere Snapshots...")
    lines = output.splitlines()
    total_snapshots = len(lines)
    print_info(f"    Insgesamt {total_snapshots} Snapshot-Einträge gefunden.")

    for line in lines:
        if not line.strip(): continue
        try:
            full_snapshot_name, creation_ts_str = line.strip().split('\t', 1)
            creation_ts = int(creation_ts_str)
        except ValueError:
            print_warning(f"[!] Warnung: Konnte Snapshot-Zeile nicht parsen: {line}")
            continue

        match = snapshot_pattern.match(full_snapshot_name)
        if not match:
            print_warning(f"[!] Warnung: Konnte Dataset/Snapshot-Namen nicht aus '{full_snapshot_name}' extrahieren.")
            continue

        dataset_name = match.group(1)
        snapshot_short_name = match.group(2)

        all_snapshots_by_dataset[dataset_name].append({
             'full_name': full_snapshot_name,
            'short_name': snapshot_short_name,
            'creation': creation_ts
        })

    grouped_guests = defaultdict(lambda: {'type': None, 'id': None, 'name': None, 'datasets': defaultdict(lambda: {'snapshots': []})})
    guest_disk_pattern = re.compile(rf'^{re.escape(remote_pool_base.rstrip("/"))}/(vm|subvol)-(\d+)-disk-\d+$')

    print_info("[*] Gruppiere Datasets nach Gast-IDs...")
    processed_guests_info = {}

    for dataset, snapshots in all_snapshots_by_dataset.items():
        guest_match = guest_disk_pattern.match(dataset)
        if guest_match:
            guest_type_prefix = guest_match.group(1)
            guest_id = int(guest_match.group(2))
            guest_type = "VM" if guest_type_prefix == "vm" else "LXC"

            if guest_id not in processed_guests_info:
                 print_info(f"   -> Finde Gast {guest_type} {guest_id}...")
                 guest_name = get_guest_name(host, user, guest_id, guest_type)
                 processed_guests_info[guest_id] = {'type': guest_type, 'name': guest_name}
                 grouped_guests[guest_id]['id'] = guest_id
                 grouped_guests[guest_id]['type'] = guest_type
                 grouped_guests[guest_id]['name'] = guest_name

            grouped_guests[guest_id]['datasets'][dataset]['snapshots'] = snapshots

    if not grouped_guests:
        print_info(f"[*] Keine Datasets unter '{remote_pool_base}' gefunden, die VMs oder LXCs zugeordnet werden konnten.")

    final_dict = {}
    for guest_id, data in grouped_guests.items():
        data['datasets'] = dict(data['datasets'])
        final_dict[guest_id] = data
    return final_dict

# --- Funktion zur interaktiven Auswahl der Gäste ---
def select_guests_interactively(grouped_guests):
    """Zeigt Gäste an und lässt den Benutzer interaktiv auswählen."""
    if not grouped_guests: return []

    print_info("\n[*] Verfügbare Gäste (VMs/LXCs) mit erkannten Datasets:")
    guest_list_for_selection = []
    guest_lookup = {}

    for i, guest_id in enumerate(sorted(grouped_guests.keys())):
        guest_info = grouped_guests[guest_id]
        guest_type = guest_info['type']
        guest_name = guest_info['name']
        num_datasets = len(guest_info['datasets'])
        display_text = f"{i+1:3d}: [{guest_type:3s}] {guest_id:<5d} - {guest_name} ({num_datasets} Dataset(s))"
        print(f"  {display_text}")
        guest_list_for_selection.append(guest_id)
        guest_lookup[i] = guest_id

    while True:
        try:
            selection = prompt_user(f"\n[*] Wähle Gäste zum Übertragen (Zahlen getrennt durch Leerzeichen/Komma, 'a' für alle, 'q' zum Abbrechen):").strip().lower()
            if selection == 'q':
                 print_info("[*] Abbruch durch Benutzer.")
                 sys.exit(0)
            if selection == 'a':
                selected_indices = list(range(len(guest_list_for_selection)))
                break

            parts = re.split(r'[,\s]+', selection)
            selected_indices = set()
            invalid_input = False
            for part in parts:
                if not part: continue
                try:
                    index = int(part) - 1
                    if 0 <= index < len(guest_list_for_selection):
                        selected_indices.add(index)
                    else:
                        print_warning(f"[!] Ungültiger Index: {part}. Muss zwischen 1 und {len(guest_list_for_selection)} sein.")
                        invalid_input = True
                except ValueError:
                    print_warning(f"[!] Ungültige Eingabe: '{part}' ist keine Zahl.")
                    invalid_input = True

            if invalid_input: continue
            if not selected_indices:
                 print_warning("[!] Keine gültige Auswahl getroffen.")
                 continue

            selected_indices = sorted(list(selected_indices))
            break
        except ValueError:
             print_error(f"[!] Unerwarteter Fehler bei der Eingabeverarbeitung. Bitte versuche es erneut.")

    return [guest_lookup[i] for i in selected_indices]

# --- Funktion zum Holen lokaler Snapshots ---
def get_local_snapshots(dataset_name):
    """Holt die Namen aller Snapshots für ein lokales Dataset (nur Kurznamen)."""
    cmd_list = ["zfs", "list", "-t", "snapshot", "-o", "name", "-H", "-p", "-r", dataset_name]
    result = run_command(cmd_list, check=False, capture_output=True)

    if result is None or result.returncode != 0:
        # Dataset existiert wahrscheinlich nicht, kein Fehler hier.
        return set()

    snapshot_names = set()
    snapshot_pattern = re.compile(r'^.*@(.*)$')
    for line in result.stdout.splitlines():
        line = line.strip()
        if line:
            match = snapshot_pattern.match(line)
            if match:
                snapshot_names.add(match.group(1))
    return snapshot_names

# --- Funktion zur Berechnung des relativen Pfades ---
def calculate_relative_path(base_path, full_path):
    """Berechnet den relativen Pfad eines Datasets zum Basispfad."""
    norm_base = os.path.normpath(base_path)
    norm_full = os.path.normpath(full_path)
    # Workaround für root-Datasets: commonpath mag es nicht, wenn base = '/'
    if norm_base == os.path.sep:
        if norm_full.startswith(norm_base):
            # Entferne führendes '/' und gib Rest zurück (oder '' wenn identisch)
            relative = norm_full.lstrip(os.path.sep)
            if not relative and norm_full == norm_base: # Wenn beide '/' waren
                 print_error(f"[!] Fehler: Basis- und vollständiger Pfad sind beide das Root-Verzeichnis ('/').")
                 return None
            return relative or '.' # Gebe '.' zurück, wenn full_path = '/'
        else:
            print_error(f"[!] Fehler: Pfad '{norm_full}' liegt nicht unter Basis '{norm_base}'.")
            return None

    # Standardfall für non-root base
    try:
        common = os.path.commonpath([norm_base, norm_full])
        if common != norm_base:
            print_error(f"[!] Fehler: Pfad '{norm_full}' liegt nicht unter Basis '{norm_base}'.")
            return None
        relative = os.path.relpath(norm_full, norm_base)
        if relative == '.':
             # Wenn relpath '.' zurückgibt, bedeutet dies, dass die Pfade identisch sind
             print_error(f"[!] Fehler: Dataset-Pfad '{norm_full}' ist identisch mit dem Basispfad '{norm_base}'.")
             return None
        return relative
    except ValueError as e:
        print_error(f"[!] Fehler beim Berechnen des relativen Pfads für '{norm_full}' von '{norm_base}': {e}")
        return None


# --- Funktion zur Ausführung der Send/Recv-Pipeline ---
def execute_send_recv_pipe(host, user, send_cmd_str, recv_cmd_list,
                           snapshot_full_name, # Für pv -N Option
                           estimated_size_bytes=None,
                           use_pv=False, pv_path=None):
    """
    Führt die zfs send | [pv] | ssh | zfs recv Pipeline aus.
    Gibt True bei Erfolg zurück, False bei Fehler.
    """
    PV_MIN_SIZE_BYTES = 1 * 1024 * 1024  # 1 MiB

    pv_cmd_list = []
    use_pipeline_with_pv = False

    # Prüfe, ob pv verwendet werden soll und kann
    if use_pv and pv_path:
        if estimated_size_bytes is not None and estimated_size_bytes > PV_MIN_SIZE_BYTES:
            snap_short_name = os.path.basename(snapshot_full_name)
            # Option '-c' für Cursor-Positionierung hinzugefügt
            pv_cmd_list = [pv_path, "-s", str(estimated_size_bytes), "-p", "-t", "-e", "-r", "-b", "-c", "-N", snap_short_name]
            use_pipeline_with_pv = True
        elif estimated_size_bytes is not None: # Größe bekannt, aber zu klein
             pass # Kein pv verwenden
        else: # Größe unbekannt
             print_warning(f"[*]   >> Führe Übertragung ohne 'pv'-Fortschrittsanzeige durch (Größe unbekannt).")
    elif use_pv and not pv_path:
        # pv gewünscht, aber nicht gefunden (sollte bereits geloggt sein)
        pass # Kein pv verwenden

    # Führe die Übertragungspipeline aus
    ssh_proc = None
    pv_proc = None
    recv_proc = None
    success = False

    try:
        ssh_cmd_list = ["ssh", "-o", "BatchMode=yes",
                        f"{user}@{host}", "--", send_cmd_str]

        if use_pipeline_with_pv:
            # Pipeline: ssh -> pv -> zfs recv
            # --- AUSKOMMENTIERT ---
            # print_info(f"[*]   >> Starte Übertragung mit pv (PID folgt): {' '.join(recv_cmd_list)}") # Info vor Popen
            ssh_proc = subprocess.Popen(ssh_cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # stderr=None leitet stderr von pv an den stderr des Hauptskripts weiter, wo -c wirken kann
            pv_proc = subprocess.Popen(pv_cmd_list, stdin=ssh_proc.stdout, stdout=subprocess.PIPE, stderr=None)
            # --- AUSKOMMENTIERT ---
            # if pv_proc.pid: print_info(f"[*]      pv PID: {pv_proc.pid}") # PID loggen
            ssh_proc.stdout.close() # Allow ssh_proc to receive SIGPIPE if pv_proc exits.
            recv_proc = subprocess.Popen(recv_cmd_list, stdin=pv_proc.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='replace')
            pv_proc.stdout.close() # Allow pv_proc to receive SIGPIPE if recv_proc exits.
            # WICHTIG für -c: stderr von pv geht direkt an das Terminal (da stderr=None).
            # Wir lesen hier nur stdout/stderr von recv.
            recv_stdout_str, recv_stderr_str = recv_proc.communicate()
            recv_retcode = recv_proc.returncode

            # Warte auf pv und ssh *nachdem* recv fertig ist
            pv_retcode = pv_proc.wait() # Warten auf pv
            # Lese ssh stderr erst nach wait von ssh
            ssh_stderr_bytes = ssh_proc.stderr.read()
            ssh_proc.stderr.close()
            ssh_retcode = ssh_proc.wait() # Warten auf ssh
            ssh_stderr_str = ssh_stderr_bytes.decode(sys.stderr.encoding, errors='replace').strip()

            # Fehlerprüfung (Pipeline mit pv)
            if ssh_retcode != 0:
                print_error(f"\n[!]   >> Fehler beim 'zfs send' auf {host} (SSH Exit Code: {ssh_retcode}):") # \n hinzugefügt
                send_args = send_cmd_str.replace("zfs send ", "")
                print_error(f"       Send-Args: {send_args}")
                print_error(f"       Fehler (SSH/Send stderr): {ssh_stderr_str or '(Keine stderr Ausgabe)'}")
            elif pv_retcode != 0:
                 # Normalerweise gibt pv keinen Fehler aus, außer bei Startproblemen. Der Balken selbst produziert keinen Fehler.
                 print_error(f"\n[!]   >> Fehler im 'pv'-Prozess (pv Exit Code: {pv_retcode}):") # \n hinzugefügt
                 print_error(f"       pv Befehl: {' '.join(pv_cmd_list)}")
            elif recv_retcode != 0:
                print_error(f"\n[!]   >> Fehler beim lokalen 'zfs recv' (Recv Exit Code: {recv_retcode}):") # \n hinzugefügt
                print_error(f"       Recv-Befehl: {' '.join(recv_cmd_list)}")
                print_error(f"       Fehler (Recv stderr): {recv_stderr_str.strip() or '(Keine stderr Ausgabe)'}")
                if recv_stdout_str: print_error(f"       Ausgabe (Recv stdout): {recv_stdout_str.strip()}")
            else:
                # Erfolg: Die pv-Zeile wird vom nächsten print überschrieben.
                # Ein explizites Löschen ist meist nicht nötig. Ein Zeilenumbruch kann helfen.
                print() # Fügt einen Zeilenumbruch nach erfolgreichem pv hinzu
                success = True

        else:
            # Pipeline: ssh -> zfs recv (ohne pv)
            # --- AUSKOMMENTIERT ---
            # print_info(f"[*]   >> Starte Übertragung ohne pv: {' '.join(recv_cmd_list)}")
            ssh_proc = subprocess.Popen(ssh_cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            recv_proc = subprocess.Popen(recv_cmd_list, stdin=ssh_proc.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='replace')
            ssh_proc.stdout.close() # Allow ssh_proc to receive SIGPIPE if recv_proc exits.
            recv_stdout_str, recv_stderr_str = recv_proc.communicate()
            recv_retcode = recv_proc.returncode
            ssh_stderr_bytes = ssh_proc.stderr.read() # Erst nach wait lesen
            ssh_proc.stderr.close()
            ssh_retcode = ssh_proc.wait() # Warten auf ssh
            ssh_stderr_str = ssh_stderr_bytes.decode(sys.stderr.encoding, errors='replace').strip()

            # Fehlerprüfung (Original-Pipeline)
            if ssh_retcode != 0:
                print_error(f"[!]   >> Fehler beim 'zfs send' auf {host} (SSH Exit Code: {ssh_retcode}):")
                send_args = send_cmd_str.replace("zfs send ", "")
                print_error(f"       Send-Args: {send_args}")
                print_error(f"       Fehler (SSH/Send stderr): {ssh_stderr_str or '(Keine stderr Ausgabe)'}")
            elif recv_retcode != 0:
                print_error(f"[!]   >> Fehler beim lokalen 'zfs recv' (Recv Exit Code: {recv_retcode}):")
                print_error(f"       Recv-Befehl: {' '.join(recv_cmd_list)}")
                print_error(f"       Fehler (Recv stderr): {recv_stderr_str.strip() or '(Keine stderr Ausgabe)'}")
                if recv_stdout_str: print_error(f"       Ausgabe (Recv stdout): {recv_stdout_str.strip()}")
            else:
                success = True

    except Exception as e:
        print_error(f"\n[!]   >> Unerwarteter Systemfehler während der Send/Recv-Pipeline:") # \n hinzugefügt
        print_error(f"       Send-Befehl (remote): {send_cmd_str}")
        print_error(f"       Recv-Befehl (local): {' '.join(recv_cmd_list)}")
        if use_pipeline_with_pv: print_error(f"       PV-Befehl (local): {' '.join(pv_cmd_list)}")
        print_error(f"       Fehler: {e}")
        # Prozess-Cleanup (Best Effort)
        for proc in [ssh_proc, pv_proc, recv_proc]:
            if proc and proc.poll() is None:
                try: proc.kill()
                except Exception: pass
        return False

    return success


# --- Funktion zur Synchronisation eines Datasets ---
def sync_dataset_snapshots(host, user, remote_dataset_name, remote_snapshots,
                           local_pool_base, remote_pool_base,
                           set_auto_snapshot_false, # Lokale Flag
                           use_pv=False, pv_path=None): # Flags für pv
    """Überträgt alle Snapshots eines Datasets inkrementell."""
    local_dataset_name = None
    relative_path = calculate_relative_path(remote_pool_base, remote_dataset_name)
    if relative_path is None or relative_path == '.': # Fehler oder identischer Pfad
        print_error(f"[!]   > Überspringe Dataset {remote_dataset_name} aufgrund eines Pfadproblems.")
        return False, None

    local_dataset_name = os.path.join(local_pool_base, relative_path)

    # Start der Dataset-Synchronisation
    print(f"{COLOR_MAGENTA}[*]   > Synchronisiere Dataset: {remote_dataset_name} -> {local_dataset_name}{COLOR_RESET}")
    num_remote_snaps = len(remote_snapshots)
    print_info(f"[*]   > {num_remote_snaps} Snapshot(s) auf Quelle gefunden.")

    local_snapshot_names = get_local_snapshots(local_dataset_name)
    print_info(f"[*]   > {len(local_snapshot_names)} Snapshot(s) lokal auf Ziel '{local_dataset_name}' gefunden.")

    last_common_snapshot_short_name = None
    last_common_snapshot_full_name_remote = None
    last_common_snapshot_index = -1

    remote_snapshot_short_names = {s['short_name'] for s in remote_snapshots}
    common_snapshot_short_names = local_snapshot_names.intersection(remote_snapshot_short_names)

    if common_snapshot_short_names:
        # Finde den *letzten* (neuesten) Remote-Snapshot, der auch lokal existiert
        for i, snap in enumerate(remote_snapshots): # Annahme: remote_snapshots ist nach Zeit sortiert
            if snap['short_name'] in common_snapshot_short_names:
                last_common_snapshot_index = i
                last_common_snapshot_short_name = snap['short_name']
                last_common_snapshot_full_name_remote = snap['full_name']
                # Suche weiter, um den neuesten gemeinsamen zu finden

        if last_common_snapshot_short_name:
            print_info(f"[*]   > Neuester gemeinsamer Snapshot: @{last_common_snapshot_short_name} (Index {last_common_snapshot_index})")
        else:
             # Sollte nicht passieren, wenn common_snapshot_short_names nicht leer ist
             print_warning("[!] Inkonsistenz bei der Suche nach gemeinsamen Snapshots.")
             last_common_snapshot_short_name = None
             last_common_snapshot_index = -1
    else:
        print_info(f"[*]   > Keine gemeinsamen Snapshots zwischen Quelle und Ziel gefunden.")
        last_common_snapshot_short_name = None
        last_common_snapshot_index = -1

    # Übertragung starten
    last_successfully_sent_full_name = None

    # --- Übertragungsschleife ---
    start_index = 0
    send_flags = "-F" # -F nur für den allerersten Empfang
    if last_common_snapshot_index != -1:
        # Start nach dem letzten gemeinsamen Snapshot
        start_index = last_common_snapshot_index + 1
        last_successfully_sent_full_name = last_common_snapshot_full_name_remote
        send_flags = "" # Kein -F bei inkrementellem Empfang
        if start_index >= num_remote_snaps:
            print_info("[*]   > Lokales Dataset ist bereits auf dem neuesten Stand (basierend auf gemeinsamen Snapshots).")
        else:
            print_info(f"[*]   > Sende Snapshots nach @{last_common_snapshot_short_name}...")
    elif remote_snapshots:
        # Start mit dem ersten Snapshot (voll)
        print_info("[*]   > Sende ersten Snapshot (voll)...")
        start_index = 0
        last_successfully_sent_full_name = None # Kein Inkrement-Basis für den ersten
    else:
        # Keine Remote-Snapshots vorhanden
        print_info("[*]   > Keine Snapshots auf Quelle vorhanden. Nichts zu tun für dieses Dataset.")
        start_index = 0 # Loop wird nicht ausgeführt

    all_transfers_ok = True
    for i in range(start_index, num_remote_snaps):
        current_snap = remote_snapshots[i]
        current_snap_full = current_snap['full_name']
        current_snap_short = current_snap['short_name']

        # Größe schätzen
        estimated_size_bytes = get_remote_snapshot_size(host, user, current_snap_full, last_successfully_sent_full_name)
        size_str_human = bytes_to_human_readable(estimated_size_bytes) if estimated_size_bytes is not None else "Unbekannt"
        human_readable_colored = f"{COLOR_YELLOW}{size_str_human}{COLOR_RESET}"

        # Sende-Nachricht
        log_prefix = f"({i+1}/{num_remote_snaps})"
        if last_successfully_sent_full_name:
             print(f"{COLOR_BLUE}[*]   >> Sende inkrementell {log_prefix}: ...@{os.path.basename(last_successfully_sent_full_name)} -> @{current_snap_short}{COLOR_RESET} | Geschätzte Größe: {human_readable_colored}")
             send_cmd_str = f"zfs send -i '{last_successfully_sent_full_name}' '{current_snap_full}'"
             recv_cmd_list = ["zfs", "recv", "-v", "-u", local_dataset_name] # Kein -F
        else:
             print(f"{COLOR_BLUE}[*]   >> Sende ersten Snapshot {log_prefix} (voll): @{current_snap_short}{COLOR_RESET} | Geschätzte Größe: {human_readable_colored}")
             send_cmd_str = f"zfs send '{current_snap_full}'"
             recv_cmd_list = ["zfs", "recv", "-F", "-v", "-u", local_dataset_name] # -F für den ersten

        # Übertragung ausführen
        if not execute_send_recv_pipe(host, user, send_cmd_str, recv_cmd_list,
                                      snapshot_full_name=current_snap_full, # Für pv -N
                                      estimated_size_bytes=estimated_size_bytes,
                                      use_pv=use_pv, pv_path=pv_path):
             print_error(f"[!]   >> FEHLER bei Übertragung zu @{current_snap_short}. Breche für dieses Dataset ab.")
             all_transfers_ok = False
             break # Abbruch für dieses Dataset bei Fehler
        else:
            # Erfolg: Merke diesen Snapshot als Basis für den nächsten Inkrement
            last_successfully_sent_full_name = current_snap_full
            send_flags = "" # Sicherstellen, dass -F nicht mehr verwendet wird

    # Nach der Schleife / bei Erfolg
    if all_transfers_ok:
        # Optional Auto-Snapshot LOKAL deaktivieren
        if set_auto_snapshot_false and local_dataset_name:
            print_info(f"[*]   > Prüfe/Setze LOKAL 'com.sun:auto-snapshot=false' für {local_dataset_name}...")
            set_cmd = ["zfs", "set", "com.sun:auto-snapshot=false", local_dataset_name]
            result = run_command(set_cmd, check=False, capture_output=True)

            if result is None or result.returncode != 0:
                # Nur warnen, wenn es nicht der erwartete "property already set"-Fehler ist
                if result and result.stderr and "property already set" not in result.stderr.lower() and "does not exist" not in result.stderr.lower():
                    print_warning(f"[!]   > Warnung: Konnte LOKAL 'com.sun:auto-snapshot=false' für {local_dataset_name} nicht setzen.")
                    print_warning(f"       Fehler: {result.stderr.strip()}")
                # else: War schon gesetzt, Dataset nicht (mehr) da, oder Befehl nicht gefunden
            else:
                print_success(f"[*]   > LOKALE Eigenschaft 'com.sun:auto-snapshot=false' erfolgreich gesetzt für {local_dataset_name}.")

        # Erfolgsmeldung für das Dataset nur, wenn kein Fehler auftrat
        if start_index < num_remote_snaps or not remote_snapshots: # Entweder wurden welche gesendet oder es gab keine
            print_success(f"[*]   > Synchronisation für Dataset {remote_dataset_name} erfolgreich abgeschlossen.")
            return True, local_dataset_name
        else: # Es gab Snapshots, aber der Startindex war schon am Ende -> Nichts zu tun
            # print_success(f"[*]   > Dataset {remote_dataset_name} war bereits aktuell.") # Redundant mit Log oben
            return True, local_dataset_name
    else:
        # Fehler trat in der Schleife auf
        return False, local_dataset_name


# --- Funktion zum Kopieren der Gast-Konfiguration ---
def transfer_guest_config(host, user, guest_id, guest_type):
    """Kopiert die VM- oder LXC-Konfigurationsdatei."""
    remote_config_path = ""
    local_config_dir = ""

    if guest_type == "VM":
        remote_config_path = f"{PVE_QEMU_CONF_DIR}/{guest_id}.conf"
        local_config_dir = PVE_QEMU_CONF_DIR
    elif guest_type == "LXC":
        remote_config_path = f"{PVE_LXC_CONF_DIR}/{guest_id}.conf"
        local_config_dir = PVE_LXC_CONF_DIR
    else:
         print_error(f"[!] Interner Fehler: Unbekannter Gast-Typ '{guest_type}' für ID {guest_id} in transfer_guest_config.")
         return False

    local_config_path = os.path.join(local_config_dir, f"{guest_id}.conf")

    # Prüfen, ob die Remote-Datei existiert
    check_cmd = f"test -f '{remote_config_path}'"
    remote_result = run_remote_command(host, user, check_cmd, check=False, quiet=True)
    if remote_result is None: # run_remote_command gibt None bei Fehler zurück (inkl. test exit code != 0)
        print_warning(f"[*] Konfigurationsdatei {remote_config_path} auf {host} nicht gefunden oder Test fehlgeschlagen. Überspringe Konfig-Kopie.")
        return False # Betrachte fehlende Config nicht als Erfolg

    print_info(f"[*] Kopiere Konfiguration für {guest_type} {guest_id}: {remote_config_path} -> {local_config_dir}/")

    try:
        # Sicherstellen, dass das Zielverzeichnis existiert
        os.makedirs(local_config_dir, exist_ok=True)
    except OSError as e:
        print_error(f"[!] Fehler beim Erstellen des lokalen Verzeichnisses {local_config_dir}: {e}")
        return False

    # Verwende scp zum Kopieren
    scp_cmd = ["scp",
               "-o", "BatchMode=yes",
               f"{user}@{host}:{remote_config_path}", # Quelle
               local_config_dir] # Zielverzeichnis

    result = run_command(scp_cmd, check=False, capture_output=True)

    if result is None or result.returncode != 0:
        print_error(f"[!] Fehler beim Kopieren der Konfiguration für {guest_type} {guest_id} festgestellt.")
        if result and result.stderr: print_error(f"    SCP Fehler: {result.stderr.strip()}")
        return False
    else:
        print_success(f"[*] Konfiguration für {guest_type} {guest_id} erfolgreich nach {local_config_path} kopiert.")
        return True

# --- Funktion zum Setzen von ZFS-Properties auf dem Remote-Host ---
def set_remote_zfs_property(host, user, dataset_name, property_name, value=None, inherit=False):
    """Setzt oder erbt eine ZFS-Property auf einem Remote-Dataset."""
    log_basename = os.path.basename(dataset_name)
    if inherit:
        if value:
            print_error(f"[!] Interner Fehler: inherit=True und value='{value}' können nicht gleichzeitig verwendet werden.")
            return False
        cmd = f"zfs inherit {property_name} '{dataset_name}'"
        log_msg_start = f"[*]   > Versuche Property '{property_name}' für Remote-Dataset {log_basename} zu erben..."
        log_msg_success = f"[+]   > Property '{property_name}' für Remote-Dataset {log_basename} erfolgreich geerbt/zurückgesetzt."
        log_msg_fail = f"[!]   > Warnung: Konnte Property '{property_name}' für Remote-Dataset {log_basename} nicht erben/zurücksetzen."
    elif value is not None:
        cmd = f"zfs set {property_name}='{value}' '{dataset_name}'"
        log_msg_start = f"[*]   > Versuche Remote-Dataset {log_basename} Property '{property_name}' auf '{value}' zu setzen..."
        log_msg_success = f"[+]   > Property '{property_name}={value}' für Remote-Dataset {log_basename} erfolgreich gesetzt."
        log_msg_fail = f"[!]   > Warnung: Konnte Property '{property_name}={value}' für Remote-Dataset {log_basename} nicht setzen."
    else:
        print_error(f"[!] Interner Fehler: Entweder value oder inherit=True muss für set_remote_zfs_property angegeben werden.")
        return False

    print_info(log_msg_start)
    # Verwende check=False, da ZFS auch bei "Erfolg" (z.B. property already set) manchmal != 0 zurückgibt
    result_stdout = run_remote_command(host, user, cmd, check=False, quiet=True)

    # run_remote_command gibt None zurück, wenn der SSH-Befehl selbst fehlschlägt
    if result_stdout is None:
        # Fehler auf SSH-Ebene oder Befehlsausführung fehlgeschlagen (bereits geloggt)
        print_warning(log_msg_fail)
        # Versuch, den Fehler explizit anzuzeigen
        run_remote_command(host, user, cmd, check=False, quiet=False)
        return False
    else:
        # Der Befehl wurde ausgeführt. ZFS kann trotzdem einen Fehler gemeldet haben (der aber nicht zum Abbruch führte)
        # oder erfolgreich gewesen sein. Wir geben optimistisch Erfolg zurück.
        # Ein expliziter check auf z.B. "property already set" wäre möglich, aber komplex.
        print_success(log_msg_success)
        return True


# --- Hauptlogik ---
def main(args):
    print(f"\n{COLOR_BOLD}--- PVE ZFS Gast Übernahme Skript (VMs & LXCs) ---{COLOR_RESET}")

    if os.geteuid() != 0:
        print_error("[!] Dieses Skript benötigt lokale root-Rechte (z.B. via sudo) für 'zfs recv' und 'scp' in Systemverzeichnisse.")
        sys.exit(1)

    # --- Werte ermitteln: Interaktiv vs. Argumente ---
    interactive_mode = not any(arg_val for arg_name, arg_val in vars(args).items()
                               if arg_name not in ['func', 'yes'] and arg_val is not None and arg_val != []) \
                       or (not args.host and not args.guests) # Explizit prüfen, ob Host/Guests fehlen

    pv_path = shutil.which("pv")
    if pv_path:
        print_info(f"[*] Fortschrittsanzeige-Tool 'pv' gefunden: {pv_path}")
        enable_pv = True
    else:
        print_warning("[!] Fortschrittsanzeige-Tool 'pv' nicht im lokalen PATH gefunden.")
        print_warning("    -> Die Übertragung wird ohne Fortschrittsbalken durchgeführt.")
        print_warning("    -> Optional: Installiere 'pv' (z.B. 'apt install pv').")
        enable_pv = False

    if interactive_mode:
        print_info("\n[*] Interaktiver Modus gestartet (keine oder unvollständige Argumente angegeben).")
        remote_host = prompt_user("[?] IP-Adresse oder Hostname des Quell-PVE-Hosts:").strip()
        if not remote_host:
            print_error("[!] Ungültige Eingabe für den Quell-Host.")
            sys.exit(1)
        # Defaults aus argparse holen, falls im interaktiven Modus nichts eingegeben wird
        ssh_user = prompt_user(f"[?] SSH-Benutzer für {remote_host} (leer für '{args.user}'):").strip() or args.user
        remote_pool_base = prompt_user(f"[?] Basis-Pfad des ZFS-Pools auf QUELLE {remote_host} (leer für '{args.remote_pool}'):").strip() or args.remote_pool
        local_pool_base = prompt_user(f"[?] Basis-Pfad des ZFS-Pools auf ZIEL (dieses System) (leer für '{args.local_pool}'):").strip() or args.local_pool
        # Flags interaktiv abfragen
        create_new_snapshot = False # Initialisierung
        set_auto_snapshot_false_on_target = False # Initialisierung
        disable_remote_auto_snapshot_temporarily = True # Default Ja

        confirm_final = False # Wird später abgefragt
    else:
        print_info("\n[*] Nicht-interaktiver Modus (Argumente angegeben).")
        if not args.host or not args.guests:
             print_error("[!] Fehler: Im nicht-interaktiven Modus müssen --host und --guests angegeben werden.")
             print_error("    Benutze -h oder --help für Hilfe.")
             sys.exit(1)
        remote_host = args.host
        ssh_user = args.user
        remote_pool_base = args.remote_pool
        local_pool_base = args.local_pool
        # Flags direkt aus args nehmen
        create_new_snapshot = args.create_snapshot
        set_auto_snapshot_false_on_target = args.set_target_noautosnap
        # Logik für --disable-source-autosnap / --no-disable-source-autosnap
        if args.no_disable_source_autosnap:
            disable_remote_auto_snapshot_temporarily = False
        else:
            # Default ist True (wie args.disable_source_autosnap), es sei denn, --no-... ist gesetzt
            disable_remote_auto_snapshot_temporarily = args.disable_source_autosnap # Default war True

        confirm_final = args.yes # Bestätigung überspringen?

    # --- Gemeinsame Initialisierung nach Variablensetzung ---
    print_info(f"[*] Verwende folgende Konfiguration:")
    print(f"    Quell-Host:           {remote_host}")
    print(f"    SSH Benutzer:          {ssh_user}")
    print(f"    Remote ZFS Pool Basis: {remote_pool_base}")
    print(f"    Lokaler ZFS Pool Basis:  {local_pool_base}")

    print_info(f"\n[*] Teste SSH-Verbindung zu {ssh_user}@{remote_host}...")
    if run_remote_command(remote_host, ssh_user, "echo 'SSH OK'", check=False) is None:
        print_error("[!] SSH-Verbindungstest fehlgeschlagen. Überprüfe Host, Benutzer, Netzwerk und SSH-Schlüssel.")
        sys.exit(1)
    else:
        print_success("[+] SSH-Verbindung erfolgreich.")

    # Prüfe auf zfs-auto-snapshot remote und lokal
    print_info(f"[*] Prüfe auf 'zfs-auto-snapshot' auf Remote-Host {remote_host}...")
    check_remote_cmd = "command -v zfs-auto-snapshot"
    remote_auto_snapshot_path = run_remote_command(remote_host, ssh_user, check_remote_cmd, check=False, quiet=True)
    remote_auto_snapshot_found = bool(remote_auto_snapshot_path)
    if remote_auto_snapshot_found:
        print_info(f"    -> 'zfs-auto-snapshot' auf {remote_host} gefunden: {remote_auto_snapshot_path}")
    else:
        print_info(f"    -> 'zfs-auto-snapshot' auf {remote_host} nicht gefunden.")

    print_info(f"[*] Prüfe auf 'zfs-auto-snapshot' auf lokalem Host...")
    local_auto_snapshot_path = shutil.which("zfs-auto-snapshot")
    local_auto_snapshot_found = local_auto_snapshot_path is not None
    if local_auto_snapshot_found:
        print_info(f"    -> 'zfs-auto-snapshot' lokal gefunden: {local_auto_snapshot_path}")
    else:
        print_info(f"    -> 'zfs-auto-snapshot' lokal nicht gefunden.")

    # --- Interaktive Abfragen für Flags (nur wenn nötig) ---
    if interactive_mode:
        if remote_auto_snapshot_found:
            while True:
                snap_choice = prompt_user(f"\n[?] Auf Quelle ({remote_host}) vor Start neuen 'daily' Snapshot erstellen? (j/N):").strip().lower()
                if snap_choice == 'j': create_new_snapshot = True; break
                elif snap_choice in ('n', ''): create_new_snapshot = False; break
                else: print_warning("[!] Ungültige Eingabe. Bitte 'j' oder 'n' eingeben.")
        else:
            print_info("\n[*] Überspringe Frage nach neuem Snapshot auf Quelle ('zfs-auto-snapshot' nicht gefunden).")
            create_new_snapshot = False

        if local_auto_snapshot_found:
            while True:
                prop_choice = prompt_user(f"[?] Für empfangene Datasets auf ZIEL 'com.sun:auto-snapshot=false' setzen? (j/N):").strip().lower()
                if prop_choice == 'j': set_auto_snapshot_false_on_target = True; break
                elif prop_choice in ('n', ''): set_auto_snapshot_false_on_target = False; break
                else: print_warning("[!] Ungültige Eingabe. Bitte 'j' oder 'n' eingeben.")
        else:
            print_info("[*] Überspringe Frage nach Deaktivierung von Auto-Snapshot auf ZIEL ('zfs-auto-snapshot' lokal nicht gefunden).")
            set_auto_snapshot_false_on_target = False

        if remote_auto_snapshot_found:
            while True:
                # Default ist Ja, wie im nicht-interaktiven Modus
                remote_prop_choice = prompt_user(f"[?] Auf Quelle ({remote_host}) 'zfs-auto-snapshot' für ausgewählte Datasets temporär deaktivieren (empfohlen)? (J/n):").strip().lower()
                if remote_prop_choice == 'n': disable_remote_auto_snapshot_temporarily = False; break
                elif remote_prop_choice in ('j', ''): disable_remote_auto_snapshot_temporarily = True; break
                else: print_warning("[!] Ungültige Eingabe. Bitte 'j' oder 'n' eingeben.")
        else:
            disable_remote_auto_snapshot_temporarily = False # Kann nicht deaktiviert werden, wenn nicht vorhanden

    # --- Aktionen vor der Gastauswahl ---
    if create_new_snapshot:
        if not remote_auto_snapshot_found:
             print_warning("\n[!] Option --create-snapshot ignoriert, da 'zfs-auto-snapshot' auf Quelle nicht gefunden wurde.")
        else:
            print_info(f"\n[*] Erstelle neuen 'daily' Snapshot auf {remote_host} via zfs-auto-snapshot...")
            snap_cmd = f"zfs-auto-snapshot --label=daily --recursive '{remote_pool_base}'"
            # Verwende check=False, da der Befehl fehlschlagen kann, aber wir weitermachen wollen
            snap_result_stdout = run_remote_command(remote_host, ssh_user, snap_cmd, check=False)
            if snap_result_stdout is None: # Heißt, SSH oder Befehlsausführung schlug fehl
                print_warning(f"[!] Warnung: Befehl zur Snapshot-Erstellung auf {remote_host} fehlgeschlagen oder Tool nicht gefunden. Fahre trotzdem fort...")
            else:
                # Befehl wurde ausgeführt, kann aber intern Fehler gemeldet haben (wird in stdout stehen)
                print_success("[+] Befehl zur Snapshot-Erstellung auf Quelle erfolgreich abgesetzt.")
                if snap_result_stdout: print_info(f"    Ausgabe: {snap_result_stdout}")
                print_info("[*] Warte kurz, damit der Snapshot erstellt werden kann...")
                time.sleep(5)

    # --- Gäste holen und auswählen ---
    all_guests_data = get_grouped_guests(remote_host, ssh_user, remote_pool_base)
    if not all_guests_data:
        print_info("[*] Keine übertragbaren Gäste gefunden oder Fehler beim Abrufen. Skript wird beendet.")
        sys.exit(0)

    selected_guest_ids = []
    if interactive_mode:
        selected_guest_ids = select_guests_interactively(all_guests_data)
    else:
        # Nicht-interaktive Gastauswahl basierend auf --guests
        available_ids = {str(gid) for gid in all_guests_data.keys()} # Als Strings für einfachen Vergleich
        available_guest_ids_int = set(all_guests_data.keys())

        raw_guest_selection = args.guests
        if not raw_guest_selection: # Sollte durch argparse eigentlich nicht passieren, aber sicher ist sicher
            print_error("[!] Fehler: Keine Gäste in --guests angegeben im nicht-interaktiven Modus.")
            sys.exit(1)
        
        # Prüfe, ob 'all' als einziges Element übergeben wurde
        is_all_selection = len(raw_guest_selection) == 1 and raw_guest_selection[0].lower() == 'all'

        if is_all_selection:
             selected_guest_ids = sorted(list(available_guest_ids_int))
             print_info("[*] Option '--guests all' gewählt: Alle gefundenen Gäste werden ausgewählt.")
        else:
            valid_selected_ids = set()
            invalid_inputs = []
            for guest_str in raw_guest_selection:
                if guest_str.isdigit():
                    guest_int = int(guest_str)
                    if guest_int in available_guest_ids_int:
                        valid_selected_ids.add(guest_int)
                    else:
                        invalid_inputs.append(f"{guest_str} (nicht verfügbar)")
                else:
                    invalid_inputs.append(f"{guest_str} (keine Zahl)")

            if invalid_inputs:
                print_error(f"[!] Ungültige oder nicht verfügbare Gast-IDs in --guests angegeben: {', '.join(invalid_inputs)}")
                print_error(f"    Verfügbare IDs: {', '.join(sorted(list(available_ids))) or 'Keine'}")
                sys.exit(1)
            selected_guest_ids = sorted(list(valid_selected_ids))

    if not selected_guest_ids:
        print_info("[*] Keine Gäste zur Übertragung ausgewählt oder gefunden. Skript wird beendet.")
        sys.exit(0)

    # --- Zusammenfassung und Bestätigung ---
    print_info("\n[*] Folgende Gäste wurden zur Übertragung ausgewählt:")
    selected_remote_datasets = []
    for guest_id in selected_guest_ids:
        guest_info = all_guests_data[guest_id]
        print(f"  - [{guest_info['type']}] {guest_id} - {guest_info['name']}")
        selected_remote_datasets.extend(guest_info['datasets'].keys())
    selected_remote_datasets = sorted(list(set(selected_remote_datasets))) # Eindeutige, sortierte Liste

    if disable_remote_auto_snapshot_temporarily and selected_remote_datasets:
        # Nur eine Warnung ausgeben, wenn es auch remote gefunden wurde
        if remote_auto_snapshot_found:
            print_warning(f"\n[!] Hinweis: 'zfs-auto-snapshot' wird auf {remote_host} für die {len(selected_remote_datasets)} Quell-Datasets der ausgewählten Gäste deaktiviert (falls möglich).")
        else:
             # An dieser Stelle sollte disable_remote_auto_snapshot_temporarily = False sein, wenn nicht gefunden.
             # Sicherheitshalber aber eine Info.
             print_info(f"\n[*] Hinweis: Temporäres Deaktivieren von Auto-Snapshot auf Quelle übersprungen ('zfs-auto-snapshot' nicht gefunden).")

    if not confirm_final: # Wenn -y nicht gesetzt wurde (oder interaktiv)
        if interactive_mode:
            confirm = prompt_user("\n[?] Fortfahren mit der Übertragung ALLER Snapshots dieser Gäste und ihrer Konfiguration? (j/N):").strip().lower()
            if confirm != 'j':
                print_info("[*] Abbruch durch Benutzer.")
                sys.exit(0)
        else:
             print_warning(f"\n[!] Nicht-interaktiver Modus: Die Übertragung wurde NICHT gestartet, da die Option -y / --yes fehlt.")
             print_warning("    Fügen Sie -y hinzu, um die Übertragung ohne diese Bestätigung zu starten.")
             sys.exit(0)

    # --- Start der Übertragung ---
    print_info(f"\n{COLOR_BOLD}--- Starte Gast Übertragungen ---{COLOR_RESET}")
    overall_success_count = 0
    overall_fail_count = 0
    total_selected_guests = len(selected_guest_ids)
    datasets_with_local_auto_snapshot_disabled = [] # Speichert lokale Dataset-Namen
    remote_datasets_auto_snapshot_disabled = [] # Speichert remote Dataset-Namen

    # Temporär Remote Auto-Snapshot deaktivieren (nur wenn gewünscht UND möglich)
    if disable_remote_auto_snapshot_temporarily and remote_auto_snapshot_found and selected_remote_datasets:
        print_info(f"\n[*] Deaktiviere temporär 'com.sun:auto-snapshot' auf Quelle ({remote_host}) für {len(selected_remote_datasets)} ausgewählte Datasets...")
        disable_success_count = 0
        for dataset_name in selected_remote_datasets:
            # Versuche 'false' zu setzen
            if set_remote_zfs_property(remote_host, ssh_user, dataset_name, "com.sun:auto-snapshot", value="false", inherit=False):
                remote_datasets_auto_snapshot_disabled.append(dataset_name)
                disable_success_count += 1
            # Wenn das Setzen fehlschlägt, versuchen wir nicht, es später wieder zu aktivieren
        if disable_success_count < len(selected_remote_datasets):
             print_warning(f"[!] Konnte Auto-Snapshot nicht für alle {len(selected_remote_datasets)} Datasets auf Quelle deaktivieren ({disable_success_count} erfolgreich).")
        elif disable_success_count > 0:
             print_success(f"[+] Auto-Snapshot auf Quelle erfolgreich für {disable_success_count} Datasets deaktiviert.")
    elif disable_remote_auto_snapshot_temporarily and not remote_auto_snapshot_found:
         print_info("[*] Temporäres Deaktivieren von Auto-Snapshot auf Quelle übersprungen (Tool nicht gefunden).")


    # --- Hauptschleife über ausgewählte Gäste ---
    try:
        for i, guest_id in enumerate(selected_guest_ids):
            guest_info = all_guests_data[guest_id]
            guest_type = guest_info['type']
            guest_name = guest_info['name']
            # Hole die Datasets für *diesen* Gast
            # Wichtig: Filtere erneut nach den *global* ausgewählten Datasets, falls ein Gast Datasets hat,
            # die nicht zu den ausgewählten gehören (sollte nicht passieren, aber sicher ist sicher).
            datasets_to_transfer = {
                ds_name: ds_info for ds_name, ds_info in guest_info['datasets'].items()
                if ds_name in selected_remote_datasets
            }
            num_datasets = len(datasets_to_transfer)

            if not datasets_to_transfer:
                 print_warning(f"[!] Keine zu übertragenden Datasets für Gast {guest_id} ({guest_name}) gefunden (möglicherweise nicht in ursprünglicher Auswahl). Überspringe.")
                 continue

            print(f"\n{COLOR_BLUE}{COLOR_BOLD}[*] Beginne Gast {i+1}/{total_selected_guests}: [{guest_type}] {guest_id} - {guest_name} ({num_datasets} Dataset(s))...{COLOR_RESET}")

            all_datasets_synced_for_guest = True
            successful_dataset_count = 0
            dataset_index = 0
            sorted_dataset_names = sorted(datasets_to_transfer.keys())

            for remote_dataset_name in sorted_dataset_names:
                 dataset_info = datasets_to_transfer[remote_dataset_name]
                 # Diese Prüfung ist jetzt redundant durch die Filterung oben, schadet aber nicht.
                 # if remote_dataset_name not in selected_remote_datasets:
                 #     print_warning(f"[!] (Intern) Überspringe Dataset {os.path.basename(remote_dataset_name)} für Gast {guest_id}, da es nicht Teil der ursprünglichen Auswahl war.")
                 #     continue

                 dataset_index += 1
                 remote_snapshots = dataset_info['snapshots']
                 print_info(f"[*]    Dataset {dataset_index}/{num_datasets} für Gast {guest_id}: {os.path.basename(remote_dataset_name)}")
                 # Snapshots nach Erstellungsdatum sortieren (wichtig für inkrementelle Übertragung)
                 remote_snapshots.sort(key=lambda s: s['creation'])

                 # Dataset synchronisieren
                 sync_successful, local_dataset_name_processed = sync_dataset_snapshots(
                     host=remote_host, user=ssh_user,
                     remote_dataset_name=remote_dataset_name,
                     remote_snapshots=remote_snapshots,
                     local_pool_base=local_pool_base,
                     remote_pool_base=remote_pool_base,
                     set_auto_snapshot_false=set_auto_snapshot_false_on_target, # Flag für lokale Aktion
                     use_pv=enable_pv, pv_path=pv_path
                 )

                 if not sync_successful:
                     all_datasets_synced_for_guest = False
                     print_error(f"[!]   FEHLER bei Synchronisation von Dataset {os.path.basename(remote_dataset_name)} für Gast {guest_id}.")
                     # Breche *nicht* notwendigerweise für den ganzen Gast ab, versuche die anderen Datasets
                 else:
                    successful_dataset_count += 1
                    # Merke dir das lokale Dataset, falls die lokale Property gesetzt wurde
                    if set_auto_snapshot_false_on_target and local_dataset_name_processed:
                         if local_dataset_name_processed not in datasets_with_local_auto_snapshot_disabled:
                             datasets_with_local_auto_snapshot_disabled.append(local_dataset_name_processed)

            # Nach allen Datasets für diesen Gast: Konfiguration kopieren?
            config_transferred = False
            if successful_dataset_count == num_datasets:
                print_success(f"[*] Alle {successful_dataset_count} relevanten Datasets für Gast {guest_id} erfolgreich synchronisiert.")
                if transfer_guest_config(remote_host, ssh_user, guest_id, guest_type):
                    config_transferred = True
                else:
                    # Fehler beim Config-Kopieren zählt als Fehler für den Gast
                    print_error(f"[!] Konfiguration für Gast {guest_id} konnte NICHT kopiert werden (Datei nicht gefunden oder Fehler).")
                    all_datasets_synced_for_guest = False # Setze Gast-Status auf fehlerhaft
            elif successful_dataset_count < num_datasets:
                 print_warning(f"[!] Nicht alle Datasets für Gast {guest_id} konnten synchronisiert werden ({successful_dataset_count}/{num_datasets} erfolgreich). Konfiguration wird NICHT kopiert.")
                 all_datasets_synced_for_guest = False # Setze Gast-Status auf fehlerhaft
            else: # successful_dataset_count > num_datasets (sollte nie passieren)
                 print_error(f"[!] Inkonsistenz: Zähler ({successful_dataset_count}/{num_datasets}) stimmt nicht für Gast {guest_id}.")
                 all_datasets_synced_for_guest = False # Setze Gast-Status auf fehlerhaft


            # Gast-Gesamtstatus bewerten
            if all_datasets_synced_for_guest and config_transferred:
                print_success(f"[+] Übertragung für Gast {guest_id} ({guest_name}) erfolgreich abgeschlossen (alle Datasets + Konfig).")
                overall_success_count += 1
            else:
                 # Fehler bei Datasets ODER Config
                 print_error(f"[!] Übertragung für Gast {guest_id} ({guest_name}) MIT FEHLERN abgeschlossen.")
                 overall_fail_count += 1

    finally:
        # Remote Auto-Snapshot wieder aktivieren (nur für die, die erfolgreich deaktiviert wurden)
        if remote_datasets_auto_snapshot_disabled:
            print_info(f"\n[*] Aktiviere 'com.sun:auto-snapshot' (via inherit) auf Quelle ({remote_host}) wieder für {len(remote_datasets_auto_snapshot_disabled)} Datasets...")
            reenable_success = 0
            reenable_fail = 0
            for dataset_name in remote_datasets_auto_snapshot_disabled:
                # Versuche 'inherit'
                if set_remote_zfs_property(remote_host, ssh_user, dataset_name, "com.sun:auto-snapshot", inherit=True):
                    reenable_success += 1
                else:
                     reenable_fail +=1
            if reenable_fail > 0:
                 print_warning(f"[!] Konnte Auto-Snapshot nicht für {reenable_fail} von {len(remote_datasets_auto_snapshot_disabled)} Datasets auf Quelle reaktivieren. Bitte manuell prüfen!")
            elif reenable_success > 0 :
                 print_success(f"[+] Auto-Snapshot auf Quelle erfolgreich für {reenable_success} Datasets reaktiviert.")

    # --- Abschlussbericht ---
    print_info(f"\n{COLOR_BOLD}--- Gast Übertragungen abgeschlossen ---{COLOR_RESET}")
    print_success(f"[*] {overall_success_count} von {total_selected_guests} ausgewählten Gästen vollständig erfolgreich übertragen (alle Datasets + Konfig).")
    if overall_fail_count > 0:
        print_error(f"[!] {overall_fail_count} von {total_selected_guests} ausgewählten Gästen mit Fehlern bei Datasets oder Konfiguration abgeschlossen.")

    # Hinweis auf lokal deaktivierte Auto-Snapshots
    if datasets_with_local_auto_snapshot_disabled:
         print_warning("\n[!] WICHTIG: Die Option zum Deaktivieren von Auto-Snapshots auf dem ZIEL wurde gewählt (--set-target-noautosnap).")
         print_warning("    Die Eigenschaft 'com.sun:auto-snapshot=false' wurde möglicherweise für die folgenden")
         print_warning("    lokal empfangenen Datasets gesetzt:")
         unique_local_datasets = sorted(list(set(datasets_with_local_auto_snapshot_disabled)))
         for dataset_name in unique_local_datasets:
             print(f"      - {dataset_name}")
         print_warning("\n    Um die automatischen Snapshots wieder zu AKTIVIEREN, müssen Sie die Eigenschaft")
         print_warning("    normalerweise ZURÜCKSETZEN (z.B. mit 'zfs inherit com.sun:auto-snapshot ...').")
         print_warning("    Beispiel: zfs inherit com.sun:auto-snapshot <lokales_dataset>")
    elif set_auto_snapshot_false_on_target:
         print_warning("\n[!] HINWEIS: Die Option --set-target-noautosnap wurde gewählt,")
         print_warning("    aber es wurden keine Datasets erfolgreich übertragen und modifiziert, oder die Liste ist leer.")

    print(f"\n{COLOR_BOLD}--- Skript beendet ---{COLOR_RESET}")
    if overall_fail_count > 0:
        print_warning(f"\n[!] Achtung: Es sind Fehler bei mindestens einem Gast aufgetreten. Bitte überprüfen Sie die obigen Logs sorgfältig.")
        sys.exit(1)
    else:
        print_success("\n[+] Alle ausgewählten Operationen wurden scheinbar erfolgreich durchgeführt.")
        sys.exit(0)


if __name__ == "__main__":
    # Definiere die gewünschte Breite für die Options-Spalte und die Gesamtbreite
    # Passe diese Werte bei Bedarf an, um die beste Darstellung zu erzielen
    help_options_column_width = 38  # Breite für Option + Platzhalter (z.B. --guests GUESTS [GUESTS ...])
    help_total_width = 100          # Gesamtbreite der Hilfeausgabe

    parser = argparse.ArgumentParser(
        description="Überträgt PVE VMs/LXCs (ZFS-Datasets und Konfiguration) von einem Quell-PVE zu diesem System.",
        # Verwende eine Lambda-Funktion, um die Formatierungsklasse mit Parametern zu instanziieren
        formatter_class=lambda prog: argparse.RawTextHelpFormatter(
            prog,
            max_help_position=help_options_column_width, # Maximale Position für den Beginn des Hilfetexts
            width=help_total_width                     # Gesamtbreite der Ausgabe
        ),
        epilog="""Beispiele:

  Interaktiver Modus (stellt alle Fragen):
    sudo ./pve-zfs-migrate.py

  Nicht-interaktiv (alle Gäste, Standardpools, Bestätigung überspringen):
    sudo ./pve-zfs-migrate.py --host 192.168.1.10 --guests all -y

  Nicht-interaktiv (spezifische Gäste, eigener Pool, neuen Snapshot erstellen):
    sudo ./pve-zfs-migrate.py --host pve-source --guests 101 105 200 \\
      --remote-pool tank/vmdata --local-pool backup/vmdata \\
      --create-snapshot -y

  Nicht-interaktiv (Auto-Snapshot auf Quelle *nicht* deaktivieren):
    sudo ./pve-zfs-migrate.py --host 10.0.0.5 --guests 110 --no-disable-source-autosnap -y
"""
    )

    # Erforderliche Argumente für nicht-interaktiven Modus
    parser.add_argument('--host', type=str, help='IP-Adresse oder Hostname des Quell-PVE-Hosts.')
    parser.add_argument('--guests', nargs='+', type=str, metavar='GUESTS', # Metavar hinzugefügt für Klarheit
                        help='Liste der zu übertragenden Gast-IDs (z.B. 100 101\n205) oder das Wort "all".')

    # Optionale Argumente mit Standardwerten
    parser.add_argument('--user', type=str, default=DEFAULT_SSH_USER, metavar='USER', # Metavar hinzugefügt
                        help=f'SSH-Benutzer für den Quell-Host (Standard: {DEFAULT_SSH_USER}).')
    parser.add_argument('--remote-pool', type=str, default=DEFAULT_REMOTE_POOL_BASE, metavar='REMOTE_POOL', # Metavar hinzugefügt
                        help=f'Basis-Pfad des ZFS-Pools auf der QUELLE\n(Standard: {DEFAULT_REMOTE_POOL_BASE}).')
    parser.add_argument('--local-pool', type=str, default=DEFAULT_LOCAL_POOL_BASE, metavar='LOCAL_POOL', # Metavar hinzugefügt
                        help=f'Basis-Pfad des ZFS-Pools auf dem ZIEL (dieses System)\n(Standard: {DEFAULT_LOCAL_POOL_BASE}).')

    # Flags (Boolean)
    parser.add_argument('--create-snapshot', action='store_true',
                        help='Neuen "daily" Snapshot auf der Quelle vor der\nÜbertragung erstellen (benötigt zfs-auto-snapshot\nauf Quelle).')
    parser.add_argument('--set-target-noautosnap', action='store_true',
                        help="Für empfangene Datasets auf dem ZIEL\n'com.sun:auto-snapshot=false' setzen (benötigt\nzfs-auto-snapshot lokal).")

    # Flags für temporäres Deaktivieren auf Quelle (Default ist Ja, wenn Tool da)
    parser.add_argument('--disable-source-autosnap', action='store_true', default=True, # Wird unten ggf. überschrieben
                        help="Auf Quelle 'zfs-auto-snapshot' für ausgewählte Datasets\ntemporär deaktivieren (Standard: Ja, wenn\nzfs-auto-snapshot vorhanden).")
    parser.add_argument('--no-disable-source-autosnap', action='store_true',
                        help="Explizit verhindern, dass 'zfs-auto-snapshot' auf der\nQuelle deaktiviert wird (überschreibt\n--disable-source-autosnap).")


    parser.add_argument('-y', '--yes', action='store_true',
                         help='Die endgültige Bestätigungsfrage überspringen\n(für nicht-interaktiven Betrieb).')


    # Prüfen, ob nur der Skriptname oder -h/--help übergeben wurde
    # len(sys.argv) == 1 -> Nur Skriptname
    # len(sys.argv) == 2 and sys.argv[1] in ['-h', '--help'] -> Hilfe angefordert
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] in ['-h', '--help']):
         # Wenn Hilfe angefordert wurde, zeige sie an und beende.
         if len(sys.argv) == 2 and sys.argv[1] in ['-h', '--help']:
              parser.print_help()
              sys.exit(0)
         # Wenn keine Argumente, parse mit leeren Argumenten, um Defaults zu bekommen,
         # aber der interaktive Modus wird in main() ausgelöst.
         parsed_args = parser.parse_args([])
    else:
         # Parse die tatsächlich übergebenen Argumente
         parsed_args = parser.parse_args()


    try:
        main(parsed_args) # Übergebe die geparsten Argumente an main
    except KeyboardInterrupt:
        print_error("\n\n[!] Vorgang durch Benutzer abgebrochen (Strg+C).")
        sys.exit(130)
    except SystemExit as e:
        # main() oder argparse kann sys.exit() aufrufen
        sys.exit(e.code)
    except Exception as e:
         print_error(f"\n[!] Unerwarteter kritischer Fehler im Hauptprogramm: {e}")
         import traceback
         print_error("--- Traceback ---")
         traceback.print_exc(file=sys.stderr)
         print_error("--- End Traceback ---")
         sys.exit(2)