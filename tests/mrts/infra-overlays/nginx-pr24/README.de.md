# NGINX PR24 MRTS Überlagerung

**Sprache:** [English](README.md) | Deutsch

Dieses Overlay wird aus dem geöffneten MRTS PR 24 `config_infra/nginx_linux/` kopiert.
Baum. Es handelt sich um eine Framework-eigene temporäre Infrastruktur für native MRTS NGINX
Nachweise und wird vor der Verwendung gemäß `MRTS_NATIVE_ROOT` inszeniert.

Laufzeitskripte müssen nur die bereitgestellte Kopie patchen. `tools/MRTS` oder nicht bearbeiten
die kopierten Overlay-Dateien, um Laufzeitergebnisse zu ermöglichen.

Ersetzen Sie dieses Overlay durch `$MRTS_ROOT/config_infra/nginx_linux`, sobald PR 24 ist
flussaufwärts zusammengeführt.
