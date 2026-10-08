# Grenze der generischen Auswahl für die native Reject-Fixture

**Sprache:** [English](20261008-37-native-reject-generic-selection.md) | Deutsch

## Identität

| Feld | Wert |
| --- | --- |
| Change-ID | 20261008-37-native-reject-generic-selection |
| UTC-Datum | 2026-10-08 |
| Framework-Basisrevision | 8bbaa1e647c4c5b8d348027e33cc48cd7c7551d8 |
| Issue oder Pull Request | Framework-PR137-Nacharbeit |

## Motivation und Problemstellung

Die generische Gesamtauswahl nahm die ausschließlich native Reject-Quellfixture mit bewusst leerer Erwartung auf. Der echte Matrix-Selektor scheiterte deshalb vor seinen Cache-Ownership-Prüfungen. Diese Änderung betrifft die Auswahlgrenze, nicht Cache-Ownership.

## Betroffene Komponenten und Sicherheitsgrenzen

Nur die spezielle NGINX-YAML-Fixture, ein neuer Fokustest und dieses Record-Paar ändern sich. Generische Erwartungsvalidierung, native Deskriptoren, kanonische Authority, Required-Auswahl, Parent und MRTS bleiben unverändert.

## Akzeptanzkriterien

Die generische Auswahl mit FORCE_ALL_CASES schließt die ausschließlich native Fixture aus. Andere materialisierbare Fälle bleiben auffindbar. Null/True-Kontrollen und direkte Validierung bleiben strikt. Derselbe native Fall bleibt mit echtem Deskriptor ausgewählt; fehlende echte Evidenz kann kein PASS erzeugen. Das generierte Inventar bleibt unverändert.

## Untersuchte Alternativen

Veraltete HTTP403/Rule1100301-Erwartungen oder beliebige leere Erwartungen würden den nativen Vertrag falsch darstellen. Breite Änderungen am Selektor oder Validator sind unnötig.

## Implementierungsentscheidung

Nur `runtime_materializable: false` wird auf der echten nativen Quellfixture gesetzt. Bestehende generische Anwendbarkeitsprüfungen erzwingen die Trennung auch mit FORCE_ALL_CASES. Der native Katalogpfad verwendet dieses generische YAML-Executor-Flag nicht.

## Geänderte Dateien und Tests

- `tests/cases/connector-specific/nginx/phase4_body_reject.yaml`: explizite generische Nicht-Materialisierbarkeit.
- `tests/no_crs/test_native_reject_generic_discovery.py`: fünf Prüfungen für echte Gesamtauswahl, Null/True-Kontrollen, direkte Ablehnung, native Auswahl und fehlenden Nachweis.
- Dieses englisch/deutsche Record-Paar.

## Befehle und Ergebnisse

Alle Befehle verwenden RTK, den Framework-Interpreter, explizites FRAMEWORK_ROOT und externe temporäre/Cache-Wurzeln.

| Befehl | Exit-Code | Kurzes Ergebnis | Evidenz |
| --- | --- | --- | --- |
| `python -m unittest -v tests.no_crs.test_native_reject_generic_discovery` vor Fixture-Änderung | 1 | Echte generische Auswahl meldete fehlende ganzzahlige Erwartung; explizite False-Prüfungen scheiterten ebenfalls | stream-c-native-fixture-red-final.log |
| Neuer Fokustest sowie native Auswahl-, Canonical-Binding- und Source-Association-Module | 0 | 34 Tests bestanden | stream-c-native-fixture-green-final.log |
| `python ci/tools/generate-framework-contract-catalog.py --check` | 0 | Generierte Inventarbytes unverändert | Task-Befehlsausgabe |
| `python -m unittest discover -s tests/contract_api -v` | 0 | 30 Tests bestanden | stream-c-native-fixture-contract-api.log |
| `make check-documentation` | 0 | Links, Sprach-/Variablendokumentation, Repository-Pfade895/alt0 und Record-Prüfung bestanden | stream-c-native-fixture-docs.log |
| `python -m py_compile tests/no_crs/test_native_reject_generic_discovery.py`; `git diff --check`; RTK-Verifikation | 0 | Syntax-, Whitespace- und Proxy-Prüfungen bestanden | Task-Befehlsausgabe |

## Sicherheitsauswirkung

Keine Security-Remediation oder Validatorlockerung. Typisiertes Flag und direkte generische Validierung bleiben erzwungen; native Evidenz wird nicht synthetisiert.

## Dokumentation und Runtime-Evidenz

Nur das Record-Paar. Keine native Runtime-, Produktbuild- oder Lifecycle-Evidenz wurde erhoben. Kontrollierte Auswahl-/Canonical-Tests schließen keine Runtime-Lücken.

## Nicht ausgeführte Prüfungen

Produkt-Runtime, native Builds, Veröffentlichung und Remote-Sonar wurden nicht ausgeführt: Root besitzt Integration und diese Grenzen.

## Einschränkungen und Restrisiko

Die ausschließlich native YAML-Fixture scheitert weiterhin an generischer Validierung, weil der bestehende Metadata-Guard runtime_verified=false für nicht materialisierbare Eingaben verlangt; kein Capability-Feld wurde geändert. Native Required-Auswahl bleibt der Ausführungsvertrag. Der Parent-Gitlink bleibt in diesem Slice unverändert; MRTS ist read-only.

## Finaler Diff- und Review-Status

Begrenzter Vier-Dateien-Slice geprüft; keine generierten Bytes, Counts, Deskriptoren, zentrale Logik oder Schema geändert. Whitespace-/Secret-Review bestanden; normaler Commit-SHA wird bei Übergabe geliefert.
