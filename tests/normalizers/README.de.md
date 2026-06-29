# Normalisierer

**Sprache:** [English](README.md) | Deutsch

Status: eingerüstet

Normalisierer entfernen oder stabilisieren zuvor flüchtige Werte aus Artefakten
Vergleich.

Implementierter Skelettumfang:

- Zeitstempel
- Prozess-IDs
- Thread-IDs
- localhost-Ports
- absolute Pfade unter dem aktuellen Arbeitsbereich
- Transaktions-IDs
- Gängige Server-Banner

Offene Arbeiten werden in `docs/roadmap/todo-inventory.md` verfolgt:

- Die Normalisierung der Header-Reihenfolge ist nicht implementiert. Es braucht ein artefaktspezifisches
  Parser.
- Das Parsen von Audit-Log-Abschnitten ist nicht implementiert.
- Connectorspezifische Protokollformate müssen in Connector-spezifischem Code verarbeitet werden.
