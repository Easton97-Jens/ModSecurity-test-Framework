# Framework-Contract-API

**Sprache:** [English](framework-contract-api.md) | Deutsch

modsecurity_test_framework.contracts ist die unterstützte öffentliche Grenze
für Consumer, die Framework-Testinventar, Auswahl, Szenario-Metadaten,
typisierte Erwartungen, Ergebnisvalidierung oder das Fünf-Connector-CRS-Profil
benötigen. Sie ersetzt das direkte Laden von ci/checks/catalog/*.py; ein
Consumer muss weder sys.path verändern, noch ein privates Nachbarmodul
importieren oder im Framework-Checkout laufen.

## Installation und Import

Installiere einen Framework-Checkout oder ein gebautes Wheel in die
Consumer-Umgebung:

    python3 -m pip install /pfad/zu/ModSecurity-test-Framework

Verwende danach das öffentliche Modul:

    from modsecurity_test_framework.contracts import (
        describe_test,
        load_capability_manifest,
        load_profile_contract,
        load_test_catalog,
        normalize_expectation,
        select_tests,
        validate_test_result,
    )

Das Paket verwendet ein abhängigkeitsfreies PEP-517-Build-Backend und bündelt
einen payloadfreien Contract-Katalog. framework_commit wird aus einem
Source-Checkout gelesen, wenn einer verfügbar ist; ein Wheel hält den
Source-Commit während des Builds fest. Falls beides fehlt, lautet das Feld
"unavailable" statt einen Wert zu erraten.

## Operationen

| Operation | Zweck |
|---|---|
| load_test_catalog(catalog=..., profile=...) | Liefert kanonische Metadaten für paketinterne No-CRS- und YAML-Fallquellen. |
| load_capability_manifest(source) | Validiert ein Mapping oder eine begrenzte relative JSON-Capability-Datei. |
| select_tests(manifest, ...) | Wendet deklarierte Capability-Zustände an und liefert ausgewählte IDs sowie alle Auswahlzustände. |
| describe_test(id) | Liefert einen kanonischen Szenarioeintrag. |
| normalize_expectation(value) | Validiert und kanonisiert die geschlossene getaggte Erwartungsunion. |
| validate_test_result(id, result) | Validiert ein begrenztes, payloadfreies Ergebnis-Mapping gegen die Erwartung dieses Tests. |
| load_profile_contract(name) | Liefert ein festes öffentliches Profil wie five-connectors-with-crs-no-mrts. |

Inventar- und Auswahlergebnisse enthalten schema_version, framework_commit,
Profil-/Katalogkontext, IDs, Erwartungstyp und anwendbare
Szenario-Metadaten. Ein Szenarioeintrag enthält framework_test_id, display_name,
deklarierte scenario_category, sofern vorhanden, phase, area, profile,
required_capabilities, expectation und applicability. Kategorien werden
ausschließlich aus deklarierten Framework-Metadaten kopiert; sie werden nie aus
einer CRS-Rule-ID, Rule-Message, Loginhalt oder einem Pfad hergeleitet.

Die Katalogansicht no-crs-baseline bewahrt ihre 166 deklarierten
Katalogeinträge. Die Ansicht framework-yaml stellt den eingecheckten YAML-Korpus
bereit. Wenn eine YAML-Datei die materialisierte Quelle desselben generischen
No-CRS-Falls ist, zeichnet das Paket beide Quellen unter einer kanonischen
Testidentität auf, statt ein Duplikat zu erfinden. Connector-spezifische
Quellfälle bleiben getrennt, wenn ihre deklarierte Connector-Anwendbarkeit sie
zu unterschiedlichen Tests macht.

## Typisierte Erwartungen

Die Union ist geschlossen. Unbekannte Arten, unerwartete Felder, fehlerhafte
Bezeichner, doppelte Rule-IDs und Booleans in Integer-Feldern sind
Vertragsfehler.

| Art | Erforderliche strukturierte Felder |
|---|---|
| http_status | http_status (100–599) |
| intervention | action, optional http_status und rule_ids |
| action | action, optional rule_ids |
| rule_match | rule_ids |
| event | fields und/oder ein begrenzter event_type-Bezeichner |
| request_headers / response_headers | Header-Namen, niemals Header-Werte |
| request_body / response_body | Ein begrenzter Body-State, niemals Body-Inhalt |
| transport | Ein deklarierter Transport-State |
| lifecycle | Explizite Boolean-Predicates |
| cleanup | Ein deklarierter Cleanup-State |
| compound | Zwei oder mehr explizite typisierte Conditions |
| not_applicable | Ein geschlossener Anwendbarkeits-Reason |

Nur http_status und intervention dürfen einen HTTP-Status führen. Aktionen,
Events, Body-Zustände, Transport, Lifecycle, Cleanup und Anwendbarkeit werden
nicht stillschweigend in künstliche HTTP-Werte umgewandelt.

## JSON-only-CLI

Nach der Installation arbeitet das Modul aus jedem Arbeitsverzeichnis:

    python3 -m modsecurity_test_framework.contracts inventory --catalog no-crs-baseline
    python3 -m modsecurity_test_framework.contracts select --capabilities capabilities.json
    python3 -m modsecurity_test_framework.contracts describe --test-id no-crs-baseline:allow_without_marker
    python3 -m modsecurity_test_framework.contracts validate --test-id no-crs-baseline:allow_without_marker --result result.json

Jeder Befehl schreibt genau ein JSON-Objekt nach Standardausgabe. Erfolgreiche
Befehle enden mit 0. Eine Vertrags- oder Argumentverletzung endet mit 2 und
gibt nur einen stabilen Fehlercode als JSON aus; kein Exception-Text, absoluter
Hostpfad, Request-/Response-Payload, Credential oder Secret wird ausgegeben.
Andere interne Fehler enden mit 1 und internal_error.

Die Optionen --capabilities und --result akzeptieren bewusst nur relative,
reguläre, nicht verlinkte JSON-Dateien. Der Reader weist Traversal, doppelte
JSON-Keys, übergroße Dokumente und fehlerhaftes UTF-8 vor der Verarbeitung
zurück. Das ist eine explizite Caller-Input-Grenze, keine Abhängigkeit vom
aktuellen Framework-Arbeitsverzeichnis.

## Katalogpflege und Kompatibilität

Die Paketressource wird aus eingecheckten Katalog-/YAML-Quellen erzeugt, ohne
Rules, Header-Werte, Request-Bodies, Response-Bodies, Raw-Logs oder absolute
Pfade zu kopieren:

    python3 ci/tools/generate-framework-contract-catalog.py
    make check-framework-contract-catalog
    make test-contract-api

Der Generator scheitert bei mehrdeutigen Identitäten oder ungültigen
Quellmetadaten. Das API-Target prüft ihn, damit eine Fallquellenänderung das
öffentliche Inventar nicht unbemerkt veralten lässt. Sein optionaler
Ausgabepfad wird außerdem über einen deskriptorbasierten No-Follow-Lauf unter
dem physischen Framework-Root geöffnet und atomar ersetzt; ein verlinkter
Ausgabe-Parent wird abgewiesen.

Bestehende Entrypoints bleiben unterstützt:

    python3 ci/checks/catalog/no_crs_baseline.py ...
    python3 ci/checks/catalog/five_connectors_with_crs_no_mrts.py ...

Das Fünf-Connector-Legacy-Skript stellt nun für die direkte Dateikompatibilität
einen eigenen festen Framework-Nachbar-Lookup bereit. Neue Consumer sollen
weiter das öffentliche Paket nutzen und nicht von diesem Legacy-Detail
abhängen.
