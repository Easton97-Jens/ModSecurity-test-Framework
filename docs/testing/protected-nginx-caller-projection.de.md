# Projektion des geschützten NGINX-Callers

**Sprache:** [English](protected-nginx-caller-projection.md) | Deutsch

Der unveränderliche geschützte Broker erwartet einen Inline-Parent-Caller mit
fünf Jobs, standardmäßig verweigerten Berechtigungen, exakten Master-/Nicht-Fork-
Dispatch-Gates und festem Concurrencyvertrag. Ein Ein-Job-Wrapper mit Delegation
des Callers ans Framework erfüllt diesen Parser nicht. Der gewöhnliche gehostete
NGINX-Smoke bleibt ein eigener Ausführungsweg.

Framework besitzt kanonischen Caller und Ausführungs-/Testlogik in
`.github/workflows/connector-protected-nginx-root-broker-caller.yml`. Die generierte
Parentdatei `.github/workflows/run-protected-nginx-root-broker.yml` projiziert
exakt diese Bytes, ersetzt ausschließlich `workflow_call` durch
`workflow_dispatch` und ergänzt Quellrevision/-hash als Kommentare. Beide
geschützten Brokeraufrufe bleiben auf
`8ae707d72f1a8acb25d239e55e28a73cbc7522b1`, das geschützte Framework auf
`99a7985c1be92a2297b1b59208f64df6768f2cbf`. Diese geschützten Identitäten sind von
der aktuellen Frameworkrevision zur Callergenerierung getrennt.

Aus Framework mit genehmigtem Interpreter, tatsächlichem Parentpfad und exakter
Frameworkquellrevision:

```sh
rtk bypass "$PYTHON" ci/tools/generate-protected-nginx-caller.py --check \
  --parent-root "$CONNECTOR_ROOT" --framework-revision "$FRAMEWORK_SHA"
```

Nur für eine autorisierte Projektionsaktualisierung `--sync` statt `--check`
verwenden. Der Generator liest den festen regulären Blob dieses exakten
Gitobjekts, keine veränderliche Quellkopie. Unbekannte Quellbytes, symbolische
Revisionen und Symlinkziele werden zurückgewiesen. Der geprüfte Quell-SHA-256 ist
`11ee98f070a5a4c088e0c10466c0e867869f1769e5832bacf6bf2c5986a2cb3c`.
Änderungen des Quellinhalts erfordern semantische Prüfung und reguläre Pflege
des Quell-/Generatorvertrags; reine Prüfsummenanpassung reicht nicht.

Parents Komponentensynchronisierer besitzt einen eigenen Zieltyp
`framework-inline-caller`. Er liest den festen Kandidatenworkflow als begrenzte
reguläre Gitdaten, fordert den geprüften Quellhash, rekonstruiert die vorherige
Projektion und schreibt die neue innerhalb der bestehenden Transaktion. Er
importiert kein Kandidaten-Python, erfindet keine wiederverwendbaren Referenzen
und ändert keine geschützten Brokeridentitäten. Standardobjektrepository ist
Parents Framework-Submodul; isolierte Vorbereitungen können mit
`--framework-object-root` ein vorhandenes lesendes Objektrepository wählen.
Ausschließlich der exakte frühere delegierte Caller seiner festgehaltenen Basis
ist einmalig zur Migration zugelassen; veränderte/gemischte Caller scheitern.
Die eingefrorene historische Ablehnungsfixture bleibt nach Reparatur negativ.

Gezielte On-demand-Prüfungen benötigen `CONNECTOR_ROOT` mit dem tatsächlichen
Parentcheckout einschließlich unveränderlichem Broker-Gitobjekt:

```sh
rtk bypass "$PYTHON" -m unittest -v tests.ci_security.test_protected_nginx_caller_projection
rtk bypass env ON_DEMAND_TESTS=1 "$PYTHON" -m unittest -v modsecurity_connector_tests.test_protected_nginx_caller_projection
```

Das eigenständige Framework-Modul prüft zwei Generatorfälle mit seinem eigenen exakten HEAD, auch bei flachen Checkouts. Die sieben Parent-Integrationschecks benötigen explizites CONNECTOR_ROOT, den Parent-Kandidatenprojektor und das unveränderliche Broker-Gitobjekt; fehlender Kontext scheitert vor Ausführung und wird nie übersprungen.

Die Tests laden ausschließlich den exakten unveränderlichen Brokercode nach
Prüfung seines SHA-256
`4c85bf823f7c9109706394b422b46a77e24e80808571cb13c7bf1a0a47abf2eb`.
Sie belegen Annahme der echten Generierung und Ablehnung schwächerer Gates,
Schreibberechtigungen sowie falscher/veränderlicher geschützter Pins. Zusätzlich
vergleichen sie Frameworkgenerierung mit Parents typisierter Projektion und
prüfen exakte Gitlesevorgänge. Keine privilegierte Brokeraktion, kein Publisher
und keine administrative Operation wird gestartet.

Parserkompatibilität belegt ausschließlich Callerbereitschaft. Zur finalen
Lieferung mit tatsächlicher gelieferter Frameworkrevision regenerieren, das
Parent-/Frameworkpaar erhalten, gehostete Workflow-/Sicherheitsgates prüfen und
gesondert autorisierte Protected-Master-Runtimebelege liefern. Für diese reine
Callerformkorrektur ist keine neue unveränderliche Brokerveröffentlichung nötig;
ein Runtime-PASS folgt daraus nicht.
