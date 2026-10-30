# Harness – Connector-Vorlage

**Sprache:** [English](README.md) | Deutsch

Dieses Verzeichnis beschreibt die Harnessnachweise, die für einen zukünftigen Connector erwartet werden.
Es enthält absichtlich keine ausführbare Harness-Implementierung.

## Erforderliche Harnessverantwortlichkeiten

- [ ] Build-/Laufzeitvoraussetzungen vorbereiten
- [ ] Serverprozess starten
- [ ] Serverprozess stoppen
- [ ] Serverprozess neu laden, falls unterstützt
- [ ] Regeln für einen Rahmenfall anwenden
- [ ] Anforderungs-/Antwortvorrichtungen materialisieren
- [ ] eine echte HTTP-Anfrage senden
- [ ] Sammeln Sie Server-, Connector-, Audit- und Zugriffsprotokolle
- [ ] Ergebnis JSON schreiben
- [ ] fasst die PASS/FAIL/BLOCKED-Zählungen zusammen
- [ ] Bereinigen von Laufzeitartefakten, ohne globale Quellen zu löschen

## Verantwortlichkeiten der Laufzeitvariante

- [ ] Der No-CRS-Modus hält lokale YAML-Fallregeln von CRS getrennt.
- [ ] With-CRS-Modus dokumentiert CRS-Quelle und Präambelpfade.
- [ ] Variantenspezifische Erwartungen werden berücksichtigt, sofern vorhanden.
- [ ] PASS/FAIL/BLOCKED-Zeilen werden nicht ohne Beweise neu klassifiziert.

## Beweismaterial zum Aufzeichnen

```text
Command:
Exit code:
Connector:
Case scope:
Variant:
Result directory:
Summary JSON:
Logs:
```

## Nicht im Lieferumfang enthalten

Diese Vorlage definiert keine Server-APIs, Prozessverwaltungsbefehle,
Netzwerkports oder erstellen Sie Flags für einen unbekannten zukünftigen Connector.
