Generierte Datei – nicht manuell bearbeiten.

# Generierte Abdeckungszusammenfassung

**Sprache:** [English](coverage-summary.generated.md) | Deutsch

> Hinweis: Diese deutsche Datei ist eine übersetzte Begleitdatei zur generierten englischen Quelle. Maschinenlesbare Werte, Tabellen, IDs, Pfade und Metriken bleiben absichtlich unverändert. Bei einer Neuerzeugung der englischen Quelle muss diese Datei geprüft und aktualisiert werden.

- Gesamtzahl der Fälle: 540
- RESPONSE_BODY Fälle: 32
- Verifizierte Laufzeitfälle: 0
- Nicht verifizierte Laufzeitfälle: 540

## Nach Umfang
- gemeinsam: 533
- Apache: 0
- Nginx: 7
- unbekannt: 0

## Nach Quelle
- ModSecurity-Apache PR: 4
- mrts: 399
- owasp-modsecurity/ModSecurity-apache#78: 3
- unbekannt: 134

## MRTS Quellenzusammenfassung
- Insgesamt MRTS importierte Fälle: **399**
- Aktive MRTS Fälle: **0**
- Ausstehende MRTS-Fälle: **399**
- Nicht klassifizierte MRTS Fälle: **399**
- Phase 4 / RESPONSE_BODY MRTS Fälle: **110**
- Zur Laufzeit ausführbare MRTS Fälle: **0**
- MRTS Overlay-Klassifizierungen: **nicht klassifiziert(399)**
- Von Apache beobachtete Klassifizierungen: **-**
- NGINX beobachtete Klassifizierungen: **-**
- Von HAProxy beobachtete Klassifizierungen: **-**

| Corpus | Category | Definitions | Golden tests | Golden rules | Framework cases | Active | Pending | Unclassified | Phase 4 / RESPONSE_BODY | Runtime-executable |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| upstream-config-tests | runnable | 16 | 157 | 15 | 383 | 0 | 383 | 383 | 110 | 0 |
| feature-demo | optional/demo | 9 | 13 | 8 | 16 | 0 | 16 | 16 | 0 | 0 |
| upstream-generated | golden-only | - | 157 | 15 | 0 | 0 | 0 | 0 | 0 | 0 |
| framework-curated | legacy/reference | 16 | - | - | 0 | 0 | 0 | 0 | 0 | 0 |

### MRTS Golden Drift
| Reference | Generated | Golden | Matched | Mismatch | Missing generated | Extra generated |
|---|---:|---:|---:|---:|---:|---:|
| upstream_tests | 157 | 157 | 157 | 0 | 0 | 0 |
| upstream_rules | 15 | 15 | 15 | 0 | 0 | 0 |
| feature_demo_tests | 13 | 13 | 0 | 0 | 13 | 13 |
| feature_demo_rules | 8 | 8 | 7 | 1 | 0 | 0 |

- Doppelte MRTS-Regel-IDs in importierten runnable/demo-Korpora: **13**
- Nur-Gold-Referenzen unter `tools/MRTS/generated/**` und `tools/MRTS/feature_demo/generated/**` sind nur Drifteingaben.
- Feature-Demo-Fälle sind im Bericht als optional/demo sichtbar und ausstehend, es sei denn, `MODSECURITY_MRTS_INCLUDE_FEATURE_DEMO=1` besteht die Kollisionsprüfungen.

## Nach Status
- aktiv: 8
- importiert: 133
- ausstehend: 399

## Von variable/collection
- `ARGS`: 76
- `REQUEST_COOKIES_NAMES`: 64
- `ARGS_NAMES`: 62
- `REQUEST_COOKIES`: 60
- `RESPONSE_BODY`: 28
- `ARGS:q`: 18
- `REQUEST_BODY`: 10
- `XML`: 7
- `REQUEST_URI`: 7
- `ARGS:test`: 6
- `REQUEST_HEADERS_NAMES`: 5
- `ARGS:a`: 4
- `ARGS:param1`: 4
- `MULTIPART_FILENAME`: 4
- `RESPONSE_HEADERS:Set-Cookie`: 4
- `ARGS:probe`: 4
- `ARGS:chain_a`: 3
- `ARGS:chain_b`: 3
- `FILES_NAMES`: 2
- `TX:SCORE`: 2
- `REQUEST_COOKIES:USER_TOKEN`: 2
- `RESPONSE_HEADERS:Location`: 2
- `ARGS:audit`: 1
- `REQUEST_HEADERS:X-PR70-Phase`: 1
- `ARGS_POST:arg1`: 1
- `RESPONSE_HEADERS:Last-Modified`: 1
- `ARGS:foo`: 1
- `FILES`: 1
- `ARGS:name`: 1
- `FILES_COMBINED_SIZE`: 1
- `FILES:filedata1`: 1
- `XML:/*`: 1
- `REQUEST_HEADERS:X-Missing`: 1
- `REQUEST_HEADERS:X-Phase`: 1
- `ARGS_COMBINED_SIZE`: 1
- `ARGS_GET`: 1
- `ARGS_POST_NAMES`: 1
- `ARGS_POST:test`: 1
- `REQUEST_HEADERS:User-Agent`: 1
- `REQUEST_HEADERS:X-Entity-Probe`: 1
- `RESPONSE_HEADERS:Content-Type`: 1
- `RESPONSE_HEADERS:X-Missing`: 1
- `RESPONSE_HEADERS:content-type`: 1
- `RESPONSE_HEADERS:Server`: 1

## Nach Phase
- Phase 1: 105
- Phase 2: 192
- Phase 3: 114
- Phase 4: 126

## Verifizierungshinweis
- Generierte Zusammenfassungen dienen nur der Berichterstattung und ersetzen nicht den vollständigen Laufzeitnachweis aus `make smoke-all`.
- RESPONSE_BODY bleibt non-verified/non-promoted, bis ein stabiler Full-Smoke-Laufzeitnachweis vorliegt.
- Begrenzter Nachweis für Phase 4/strikter Abbruch bleibt bestehen experimental/non-promoted; Pass-Through-Zeilen beweisen nicht die vollständige RESPONSE_BODY-Unterstützung.
