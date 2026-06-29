# NGINX-spezifische Fälle

**Sprache:** [English](README.md) | Deutsch

Bei den Fällen in diesem Verzeichnis handelt es sich um reine NGINX-Nachweisproben. Sie sind mit gekennzeichnet
YAML-Metadaten wie `portable: false`, `connector: nginx` und `status`
anstatt in Statusverzeichnisse aufgeteilt zu sein.

Die PR #377 Phase-4-Fälle überprüfen `modsecurity_phase4_mode` oder das Inhaltstypprotokoll
Verhalten und HTTP 200 Pass-Through-Erhaltung. Sie überprüfen nicht
Antworttextblockierung und `RESPONSE_BODY` dürfen nicht zu `verified_variables` hinzugefügt werden.

`nginx_phase4_strict_connection_abort.yaml` bleibt früherer erwarteter Fehler, da strikter Modus
kann die Verbindung abbrechen, nachdem Header gesendet wurden, während der aktuelle Runner
bestätigt den stabilen HTTP-Status. Dies ist keine RESPONSE_BODY-Werbung.
