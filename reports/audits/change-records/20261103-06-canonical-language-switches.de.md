# Change record

**Sprache:** [English](20261103-06-canonical-language-switches.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261103-06-canonical-language-switches |
| UTC-Datum | 2026-11-03 |
| Framework-Basisrevision | 189c42d0b4362fccc732d2480935348220c287da |
| Issue oder Pull Request | Folge zu Framework #167 und Parent #443 |

## Motivation und Problemstellung

Der strikte Parent-Dokumentationsconsumer lehnte vier Sprachumschalterzeilen in drei neu gelieferten Framework-Guidepaaren ab. Das bestandene eigenständige Framework-Dokumentationsziel prüfte andere Invarianten und belegte diesen Parent-Vertrag nicht.

## Betroffene Komponenten und Sicherheitsgrenzen

Sprachumschalter-Markup in Protokoll-, Messungs-/SBOM- und geschütztem Caller-Guide, zwei illustrative JSON-Zeilen und dieses Paar. Keine ausführbaren Quellen, Pins, Schemas, Fälle oder Prüfregeln geändert.

## Akzeptanzkriterien

Exakte etablierte EN/DE-Umschalter verwenden und sämtliche übrigen Guidebytes erhalten. Native strikte Paar-/Linkchecks, vollständige Framework-Dokumentation, unveränderte Metadaten und100-Fälle-Inventar verlangen; danach frische Hosted-Checks und regulärer exakter Folgemerge.

## Untersuchte Alternativen

Checkeränderung oder Ignorieren der Moduldokumente würde den Vertrag schwächen. Stattdessen vier falsche Umschalterzeilen normalisieren und ein byteidentisches technisches JSON-Beispiel in beiden Sprachen erhalten.

## Implementierungsentscheidung

Englisch verwendet **Language:** English | Deutsch-Link; Deutsch setzt den English-Link vor | Deutsch. Bereits korrekte Umschalter bleiben byteidentisch. Drei illustrative deutsche Platzhalter auf zwei JSON-Zeilen erhalten gemeinsame englische Werte; Feldnamen, Schema-Identifier und Exportersemantik bleiben unverändert. Parent übernimmt erst den tatsächlichen geprüften Folgemerge.

## Geänderte Dateien und Tests

Vier einzeilige Umschalterkorrekturen und zwei JSON-Beispielzeilen und dieses Paar. Vorhandene strikte ordinary_pair_errors-/local_link_errors-APIs prüfen alle drei betroffenen Paare; kein neuer Test oder Checkerausnahme.

## Befehle und Ergebnisse

RTK und vorhandenes Framework-CPython3.15.2; exakte Befehle/Ergebnisse im Integrationslauf20261103T175654Z-integration, framework-doc-followup/. Strikter Dreipaar-Consumercheck, Vergleich sämtlicher übriger Inhaltsbytes, native Metadaten write/check, Inventar und vollständige Dokumentation. Veröffentlichung und aktuelle Head-CI folgen als PR-Belege.

## Sicherheitsauswirkung

Keine ausführbare oder sicherheitsrelevante Semantik, Gates, Quellen-/Pfadguards oder geschützte Identität geändert. Kanonisches Markup stellt den bestehenden Consumervertrag wieder her.

## Dokumentation und Runtime-Evidenz

Nur EN/DE-Sprachumschalter und illustrative JSON-Platzhalter geändert; keine Hostlaufzeit behauptet.13 echte Endpaarinvokationen bleiben nach finaler Parentintegration erforderlich.

## Nicht ausgeführte Prüfungen

Keine lokale Sonar-Vorprüfung/Installation/Authreparatur, Vollkampagne, Publisher- oder geschützten Dispatches. Frische Hosted-Analyse bleibt erforderlich; alte Head-Erfolge werden nicht wiederverwendet.

## Einschränkungen und Restrisiko

Nur der konkrete Parent-Consumerfehler wird behoben. Unabhängige historische Migration-Map-/Apache-/Advisorybefunde und Vollabnahmeziele bleiben getrennt.

## Finaler Diff- und Review-Status

Exakten Sechszeilendiff und übrige Bytegleichheit prüfen; native Checks und aktuelle CI müssen bestehen. Bestehende Worktrees/Nachweise bleiben erhalten.
