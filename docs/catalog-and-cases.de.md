# Katalog und Fälle

**Sprache:** [English](catalog-and-cases.md) | Deutsch

Dies ist die gepflegte Anleitung zum Framework-Fallkatalog. YAML-Fälle und die
Runner-Implementierung sind ausführbare Quellen der Wahrheit; dieses Dokument
erklärt ihr gemeinsames Modell, ohne generierte Inventare zu duplizieren.

## Quellen der Wahrheit

| Bereich | Kanonische Quelle | Zweck |
|---|---|---|
| Falldefinitionen | `tests/cases/**/*.yaml` | Regeln, Requests, Erwartungen, Metadaten und Scope |
| Auswahl und Materialisierung | `tests/runners/` | Schemavalidierung, Filterung, Fixtures und Ergebnisnormalisierung |
| No-CRS-Katalog | `ci/checks/catalog/no_crs_baseline.py` | Kanonische Auswahl und Evidence-Vertrag |
| Aktuelles Inventar | `testing/generated/coverage/case-matrix.generated.md` | Generierter Fall-Snapshot |
| Aktuelle Runtime-Sicht | `testing/generated/runtime/runtime-matrix.generated.md` | Generierte Sicht beobachteter Ergebnisse |

Das Repository behandelt weder einen generierten Bericht noch einen
Upstream-Test oder Starter-Check als Ersatz für beobachtete Connector-Evidence.

## Fallform

| Feld | Rolle |
|---|---|
| `name` | Stabile Fallidentität; Pfade dürfen sich ändern, ohne die Identität zu ändern |
| `metadata` | Scope, Status, Provenienz, Capabilities und Promotion-Grenzen |
| `rules` | Für den Fall materialisierte lokale ModSecurity-Regeln |
| `request` | Methode, Pfad, Header, Body, Multipart-Daten und Fixtures |
| `response` | Optionale Response-Fixture für Host-Harnesses |
| `expect` | Erwarteter Status sowie begrenzte Response- oder Audit-Assertions |
| `requires_crs` | Beschränkt einen Fall bei gesetztem Wert auf die With-CRS-Variante |

Verwende `expect.variants.with-crs` nur, wenn der CRS-Runtime-Kontext eine
Assertion verändert. Ändere nicht die No-CRS-Basiserwartung, um eine
With-CRS-Ausnahme zu kodieren.

## Auswahl, Status und Promotion

| Status oder Eigenschaft | Bedeutung |
|---|---|
| `active` / `imported` | Für die jeweilige Fallauswahl geeignet; kein automatischer PASS |
| `pending`, `future`, `connector-gap` oder `runtime-difference` | In Planung und generierten Berichten sichtbar, keine Promotion |
| `mapped-only` | Provenienz- oder Designzuordnung ohne ausführbaren Fallanspruch |
| `runtime_verified` | Evidence-Metadatum; ändert sich nur über den definierten Evidence-Pfad |
| `RESPONSE_BODY` | Nicht verifiziert und nicht hochgestuft, bis stabile qualifizierende Connector-Evidence vorliegt |

Fallverzeichnisse organisieren Discovery und Reporting. Sie kodieren keinen
PASS-, FAIL- oder Promotion-Zustand. Connector-spezifische Fälle liegen unter
`tests/cases/connector-specific/<connector>/`; gemeinsame Fälle bleiben nur
dann portabel, wenn ihre Annahmen tatsächlich geteilt sind.

## Imports und Provenienz

| Quellfamilie | Aktuelle Verwendung |
|---|---|
| ModSecurity v2 | Semantik- und Regressionsreferenz für abgeleitete portable Fälle |
| ModSecurity v3 | Public-API- und Regressionsreferenz für abgeleitete portable Fälle |
| ModSecurity-apache | Referenzmaterial für Apache-Hooks, Build und Regression |
| ModSecurity-nginx | Referenzmaterial für NGINX-Hooks, Filter und Regression |
| MRTS | Optionale generierte Kompatibilitätseingabe; Feature-Demo bleibt Opt-in |

Importierte YAML-Dateien halten ihre Quelle in Metadaten fest. Upstream-Harnesses,
Serverkonfiguration, Logformate und Dateien werden nicht kopiert, nur weil ein
verwandtes Verhalten nützlich ist. Ein quellabgeleiteter Fall wird erst dann zu
einer portablen Assertion, wenn seine Annahmen und das beobachtete
Host-Verhalten für den gewählten Scope geeignet sind.

## Capabilities und normalisierte Ergebnisse

Capabilities beschreiben getestetes Verhalten, nicht eine Berechtigung zum
Überspringen oder Hochstufen eines Falls. Der Runner normalisiert begrenzte
Ergebnismetadaten, damit Connector-Berichte beobachtete PASS-, FAIL-,
BLOCKED-, NOT_EXECUTABLE- und nicht hochgestufte Zustände unterscheiden können.
Er leitet keine Unterstützung aus einem Exit-Code, einem zugeordneten
Upstream-Fall oder einer Berichtszeile ab.

P1–P4-Labels, Body-Limits, Phasenreihenfolge, First-Byte-Timing und
No-Full-Response-Buffering-Claims bleiben evidence-gebunden. Ihre genauen
Validierungseingaben und Privacy-Anforderungen beschreibt
[Testing und Evidence](testing-and-evidence.de.md).

## Den Katalog aktualisieren

1. YAML-Fall hinzufügen oder ändern und Identität, Provenienz, Scope und
   Erwartung explizit halten.
2. Runner- oder Normalizer-Code nur erweitern, wenn das Fallmodell es verlangt.
3. Katalog- und Dokumentationschecks ausführen, bevor ein Bericht als aktuell gilt.
4. Matrix über ihren Generator regenerieren; ein generiertes Inventar nie von
   Hand ändern.
5. Eine Promotion nur über beobachtete Connector-Evidence festhalten.

## Historischer Kontext

Frühere quellbezogene Maps, Importpläne, Fallmatrizen und
Kompatibilitätsnotizen wurden hier zusammengeführt. Git bewahrt ihre
detaillierte Chronologie; aktuelle generierte Berichte bewahren das live und
reproduzierbar erzeugte Inventar.
