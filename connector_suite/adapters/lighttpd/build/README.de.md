# Testartefakte des Stock-Sidecars

[English](README.md)

Der Connector baut das produktive Sidecar und dessen geschlossenes Schema-2-`stock-sidecar-artifact.manifest`. Er baut oder verteilt den Runtime-Begin-Smoke nicht.

Diesen ausgewählten Test über das Framework bauen: mit `ON_DEMAND_TESTS=1`, explizitem `TEST_ROOT`, `CONNECTOR_ROOT`, `CONNECTOR_REVISION`, `CONNECTOR_TEST_PROFILE` sowie absoluten Pfaden für `MODSECURITY_INCLUDE_DIR` / `MODSECURITY_LIB_DIR`:

```sh
python -P -m connector_suite.adapters.lighttpd.build.build_runtime_begin_smoke \
  --sidecar-binary /external/product/lighttpd-stock-sidecar \
  --output-root /external/private-test-output
```

Den Framework-Interpreter mit dessen Source-`PYTHONPATH` (`TEST_ROOT:TEST_ROOT/connector_suite`) sowie `PYTHONSAFEPATH=1` und `PYTHONNOUSERSITE=1` verwenden. Das Ausgabeverzeichnis muss bereits außerhalb beider Checkouts existieren und ausschließlich dem aufrufenden Benutzer zugänglich sein.

Der Befehl gibt einen separaten Testmanifest-Pfad aus. Diesen als `STOCK_SIDECAR_TEST_MANIFEST` an den Real-Backend-Harness oder die Sidecar-Loopback-Tests übergeben. Das Manifest bindet Framework-Revision, Smoke-Quell- und Binärhash sowie Produktmanifest-Digest. Der Build prüft außerdem, dass aktuelle Produkteingaben und ModSecurity-Bibliothek zum Produktbeleg passen und sich während der Kompilierung nicht ändern. Der Real-Backend-Harness prüft beide Manifeste und verlangt weiterhin die unabhängige Artefakt-Attestierung des Betreibers.

Ein Testbuild ist kein Stock-lighttpd-Hostnachweis. Nach Änderungen an aufgezeichneten Revisionen oder Produktquellen beide Manifeste neu bauen; alte Schema-1-Produktmanifeste werden abgelehnt.
