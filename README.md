
# PVE ZFS Guest Migration Script

![Python Version](https://img.shields.io/badge/Python-3.6%2B-blue)
![License](https://img.shields.io/badge/License-GPL-green)

## :page_facing_up: Beschreibung

Dieses Python-Skript dient zur Migration von Proxmox VE VMs und LXC-Containern, deren Speicher auf ZFS-Datasets basiert. Es migriert die Daten von einem Quell-PVE-Host zu dem Ziel-PVE-Host, auf dem das Skript ausgeführt wird. Der Transfer erfolgt durch inkrementelles Senden und Empfangen _aller_ vorhandenen ZFS-Snapshots für die ausgewählten Gäste und kopiert anschließend die Konfigurationsdatei des Gastes.

## :sparkles: Features

*   Migriert PVE VMs und LXCs, die auf ZFS-Datasets gespeichert sind.
*   Nutzt `zfs send` und `zfs recv` für effiziente, inkrementelle Übertragung aller Snapshots.
*   Kopiert die Gast-Konfigurationsdateien (`/etc/pve/qemu-server/*.conf` oder `/etc/pve/lxc/*.conf`).
*   Interaktiver Modus für einfache Auswahl der zu migrierenden Gäste und Optionen.
*   Nicht-interaktiver Modus für Automatisierung über Kommandozeilenargumente.
*   Automatische Erkennung von Gast-Datasets anhand der PVE-Namenskonvention (`vm-ID-disk-N`, `subvol-ID-disk-N`).
*   Optional: Erstellung eines neuen Snapshots auf dem Quellsystem vor der Migration (erfordert `zfs-auto-snapshot` auf der Quelle).
*   Optional: Temporäres Deaktivieren der ZFS-Property `com.sun:auto-snapshot` auf den Quell-Datasets während der Übertragung (erfordert `zfs-auto-snapshot` auf der Quelle).
*   Optional: Setzen der ZFS-Property `com.sun:auto-snapshot=false` auf den _Ziel_\-Datasets nach erfolgreicher Übertragung.
*   Verwendet `pv` (falls im PATH vorhanden) zur Anzeige eines Fortschrittsbalkens während der Datenübertragung.
*   Farbige Ausgabe zur besseren Lesbarkeit.
*   Testet die SSH-Verbindung vor Beginn.

## :package: Voraussetzungen

### Ziel-Host (wo das Skript läuft):

*   Python 3
*   `root`\-Rechte (für `zfs recv`, `scp` nach `/etc/pve`)
*   `ssh` Client installiert
*   `zfs` Kommandozeilen-Tools installiert
*   `scp` Client installiert
*   _Optional:_ `pv` für Fortschrittsanzeige (z.B. `apt install pv`)
*   Muss ein Proxmox VE Host sein.

### Quell-Host:

*   `ssh` Server aktiviert und erreichbar.
*   SSH-Zugang für den Skript-Benutzer (Passwort oder Key-basiert; Key empfohlen für nicht-interaktiven Modus). Der SSH-Benutzer benötigt Rechte zur Ausführung von `zfs list`, `zfs send` und ggf. `zfs set/inherit`. (Normalerweise `root`).
*   `zfs` Kommandozeilen-Tools installiert.
*   `bash` Shell (wird für die Remote-Ausführung verwendet).
*   _Optional:_ `zfs-auto-snapshot` installiert, wenn die Snapshot-Erstellungs- oder Property-Management-Features genutzt werden sollen.
*   Muss ein Proxmox VE Host sein.

### Netzwerk:

Konnektivität zwischen Quell- und Ziel-Host (SSH Port, typischerweise 22).

### ZFS:

Sowohl Quelle als auch Ziel müssen ZFS für die zu migrierenden Gast-Speicher verwenden.

## :gear: Installation / Setup

```bash
apt update && apt install pv
git clone https://github.com/ProlegyDE/pve-zfs-migrate.git
cd pve-zfs-migrate
chmod +x pve-zfs-migrate.py
```

## :rocket: Benutzung

Das Skript muss mit `root`\-Rechten auf dem **Ziel**\-Host ausgeführt werden (z.B. via `sudo`).

### Interaktiver Modus:

Das Skript stellt alle notwendigen Fragen (Quell-Host, Benutzer, Pools, Optionen, Gast-Auswahl).

```bash
sudo ./pve-zfs-migrate.py
```

### Nicht-interaktiver Modus:

Alle Parameter werden über Kommandozeilenargumente übergeben. Nützlich für Automatisierung.

**Alle Gäste migrieren, Standard-Pools (`rpool/data`), Bestätigung überspringen:**

```bash
sudo ./pve-zfs-migrate.py --host <IP_ODER_HOSTNAME_QUELLE> --guests all -y
```

**Spezifische Gäste (IDs 101, 105, 200) migrieren, benutzerdefinierte Pools, neuen Snapshot vorher erstellen, Bestätigung überspringen:**

```bash
sudo ./pve-zfs-migrate.py --host pve-source --guests 101 105 200 \
  --remote-pool tank/vmdata --local-pool backup/vmdata \
  --create-snapshot -y
```

**Gast 110 migrieren, Auto-Snapshot auf Quelle _nicht_ temporär deaktivieren:**

```bash
sudo ./pve-zfs-migrate.py --host 10.0.0.5 --guests 110 --no-disable-source-autosnap -y
```

**Wichtige Argumente:**

*   `--host HOST`: (Erforderlich im nicht-int. Modus) IP-Adresse oder Hostname des Quell-PVE.
*   `--guests GUEST [GUEST ...]`: (Erforderlich im nicht-int. Modus) Liste der Gast-IDs oder das Wort `all`.
*   `--user USER`: SSH-Benutzer für die Quelle (Default: `root`).
*   `--remote-pool POOL`: ZFS-Basispfad auf der Quelle (Default: `rpool/data`).
*   `--local-pool POOL`: ZFS-Basispfad auf dem Ziel (Default: identisch zu `--remote-pool`).
*   `--create-snapshot`: Neuen 'daily' Snapshot auf Quelle erstellen (via `zfs-auto-snapshot`).
*   `--set-target-noautosnap`: `com.sun:auto-snapshot=false` auf Ziel-Datasets setzen.
*   `--disable-source-autosnap`: (Default: an, falls `zfs-auto-snapshot` auf Quelle da) Temporär Auto-Snapshot auf Quelle deaktivieren.
*   `--no-disable-source-autosnap`: Explizit _verhindern_, dass Auto-Snapshot auf Quelle deaktiviert wird.
*   `-y`, `--yes`: Endgültige Bestätigungsfrage überspringen.

Eine vollständige Liste der Optionen erhalten Sie mit:

```bash
./pve-zfs-migrate.py --help
```

## :hammer_and_wrench: Konfiguration

Die Standardwerte für den SSH-Benutzer (`DEFAULT_SSH_USER`) und die ZFS-Pool-Basispfade (`DEFAULT_REMOTE_POOL_BASE`, `DEFAULT_LOCAL_POOL_BASE`) können am Anfang des Skripts angepasst werden. Es wird jedoch empfohlen, diese Werte über die Kommandozeilenargumente zu überschreiben.

## :mag: Funktionsweise (vereinfacht)

1.  **Verbindung & Vorbereitung:**
    *   Das Skript testet die SSH-Verbindung zur Quelle.
    *   Es prüft optional auf das Vorhandensein von `zfs-auto-snapshot` auf Quelle und Ziel.
    *   Optional wird ein neuer Snapshot auf der Quelle erstellt.
2.  **Snapshot-Analyse:**
    *   Listet alle ZFS-Snapshots unter dem `remote-pool` auf der Quelle.
    *   Identifiziert Datasets, die zu VMs oder LXCs gehören (anhand des Namens).
    *   Gruppiert die Snapshots nach Gast-ID.
3.  **Gast-Auswahl:**
    *   Im interaktiven Modus: Zeigt eine Liste der gefundenen Gäste zur Auswahl an.
    *   Im nicht-interaktiven Modus: Verwendet die IDs aus dem `--guests` Argument.
4.  **Temporäres Deaktivieren (Optional):**
    *   Wenn `--disable-source-autosnap` aktiv ist (und nicht `--no-disable-source-autosnap` gesetzt wurde) und `zfs-auto-snapshot` auf der Quelle vorhanden ist, wird versucht, die Property `com.sun:auto-snapshot=false` für die Datasets der ausgewählten Gäste auf der Quelle zu setzen.
5.  **Datenübertragung (pro Gast, pro Dataset):**
    *   Ermittelt den neuesten gemeinsamen Snapshot zwischen Quelle und Ziel für das aktuelle Dataset.
    *   Startet eine `zfs send` Pipeline:
        *   Quelle: `zfs send [-i <common_snap>] <latest_snap>`
        *   Pipe via `ssh` zum Ziel-Host.
        *   Optional: Pipe durch `pv` auf dem Ziel für Fortschrittsanzeige.
        *   Ziel: `zfs recv [-F] [-u] <local_dataset_path>`
            *   `-F` wird nur beim _ersten_ Empfang für ein Dataset verwendet (wenn kein gemeinsamer Snapshot existiert), um ein eventuell vorhandenes Ziel-Dataset zu überschreiben.
            *   `-u` wird verwendet, um sicherzustellen, dass das Dataset nicht gemountet wird.
    *   Wiederholt dies inkrementell für alle neueren Snapshots.
6.  **Konfigurationskopie:**
    *   Wenn _alle_ Datasets eines Gastes erfolgreich übertragen wurden, wird die zugehörige `.conf`\-Datei von `/etc/pve/{qemu-server,lxc}/` auf der Quelle mittels `scp` in das entsprechende Verzeichnis auf dem Ziel kopiert.
7.  **Wiederherstellung & Abschluss:**
    *   Wenn Auto-Snapshot auf der Quelle temporär deaktiviert wurde, wird versucht, die Property per `zfs inherit com.sun:auto-snapshot ...` wieder zu reaktivieren.
    *   Optional (`--set-target-noautosnap`) wird die Property `com.sun:auto-snapshot=false` auf den _empfangenen_ Datasets auf dem Ziel gesetzt.
    *   Eine Zusammenfassung über Erfolg und Misserfolg der Gast-Migrationen wird ausgegeben.

## :warning: Wichtige Hinweise & Warnungen

*   **Ziel-Host:** Das Skript **muss** auf dem Ziel-PVE-Host ausgeführt werden.
*   **Berechtigungen:** Lokale `root`\-Rechte sind erforderlich. Der SSH-Benutzer auf der Quelle benötigt ausreichende ZFS-Rechte (normalerweise `root`).
*   **Nur ZFS:** Funktioniert nur für Gäste, deren Disks als ZFS-Datasets mit PVE-Namensschema angelegt wurden.
*   **Keine Live-Migration:** Dies ist ein **Offline**\-Migrationstool. Die Gäste sollten auf der Quelle heruntergefahren sein, um Datenkonsistenz sicherzustellen. Das Skript fährt die Gäste weder herunter noch startet es sie.
*   **Überschreiben:**
    *   **Datasets:** Wenn ein ZFS-Dataset mit dem gleichen Namen auf dem Ziel existiert und das Skript einen _vollständigen_ Stream sendet (weil kein gemeinsamer Snapshot gefunden wurde), wird die Option `zfs recv -F` verwendet. **Dies zerstört das vorhandene Ziel-Dataset und seine Snapshots unwiderruflich!** Bei inkrementellen Übertragungen wird `-F` nicht verwendet.
    *   **Konfigurationsdateien:** Eine vorhandene Konfigurationsdatei auf dem Ziel mit der gleichen Gast-ID wird überschrieben.
*   **`zfs-auto-snapshot`:** Die Funktionalität bezüglich Snapshot-Erstellung und Property-Management hängt davon ab, ob `zfs-auto-snapshot` auf Quelle bzw. Ziel installiert und funktionsfähig ist.
*   **Fehlerbehandlung:** Das Skript versucht, robust zu sein, aber Netzwerk-, SSH- oder ZFS-Fehler können auftreten. Überprüfen Sie die Ausgabe sorgfältig.
*   **Nach der Migration:** Überprüfen Sie den migrierten Gast auf dem Ziel-Host manuell (Starten, Funktionstest, Netzwerk). Eventuell müssen Netzwerkeinstellungen in der `.conf`\-Datei angepasst werden (z.B. andere Bridge). Wenn Sie `--set-target-noautosnap` verwendet haben, denken Sie daran, dass für diese Datasets keine automatischen Snapshots mehr erstellt werden, bis Sie die Property manuell zurücksetzen (z.B. `sudo zfs inherit com.sun:auto-snapshot <pool>/<dataset>`).

## :balance_scale: Lizenz
GPL-Lizenz - Siehe LICENSE für Details.

## :page_facing_up: Haftungsausschluss

Diese Software (das Python-Skript `pve-zfs-migrate.py`) wird "**wie besehen**" ("as is") zur Verfügung gestellt, ohne jegliche ausdrückliche oder stillschweigende Gewährleistung oder Garantie, einschließlich, aber nicht beschränkt auf, die Gewährleistung der Marktgängigkeit oder der Eignung für einen bestimmten Zweck.

**Die Nutzung dieses Skripts erfolgt ausschließlich auf Ihr eigenes Risiko.**

Das Skript führt potenziell **destruktive Operationen** durch, insbesondere im Zusammenhang mit ZFS-Datasets (z.B. durch `zfs recv -F`, welches Ziel-Datasets überschreiben kann) und dem Überschreiben von Konfigurationsdateien. Fehler im Skript, Fehlkonfigurationen, Missverständnisse der Funktionsweise oder unsachgemäße Anwendung können zu **schwerwiegendem und permanentem Datenverlust**, Systeminstabilität, Betriebsunterbrechungen oder anderen unvorhergesehenen Schäden führen.

**In keinem Fall haften** die Autoren, Mitwirkenden oder Personen, die die Software verbreiten, für Schäden jeglicher Art (einschließlich, aber nicht beschränkt auf, direkte, indirekte, zufällige, besondere, exemplarische oder Folgeschäden, wie z.B. Datenverlust, Beschädigung von Systemen, Betriebsunterbrechung, entgangenen Gewinn oder andere finanzielle oder materielle Verluste), die sich aus der Nutzung, der versuchten Nutzung oder der Unmöglichkeit der Nutzung der Software ergeben, selbst wenn auf die Möglichkeit solcher Schäden hingewiesen wurde.

Es liegt in der **alleinigen Verantwortung des Benutzers**:
*   Die Funktionsweise des Skripts und die Auswirkungen der gewählten Optionen **vollständig zu verstehen**, bevor es ausgeführt wird.
*   Das Skript vor dem Einsatz in einer produktiven, kritischen oder anderweitig wichtigen Umgebung **gründlich in einer isolierten und sicheren Testumgebung** zu evaluieren.
*   Sicherzustellen, dass **vollständige, aktuelle und überprüfte Backups** aller relevanten Daten, Konfigurationen und Systeme vorhanden sind, _bevor_ das Skript ausgeführt wird.

Durch das Herunterladen, Kopieren, Ausführen oder anderweitige Nutzen dieser Software erklären Sie sich ausdrücklich mit diesem Haftungsausschluss einverstanden und erkennen an, dass Sie die damit verbundenen Risiken verstehen und akzeptieren. Wenn Sie mit diesen Bedingungen nicht einverstanden sind, dürfen Sie die Software nicht verwenden.
