# v3 API Smoke Probe Source

The canonical connector-free smoke probe source lives in:

```text
src/v3-api-smoke/v3_api_smoke.c
```

`tests/common` keeps this pointer because the probe is a portable
libmodsecurity v3 API check, but it must not duplicate the implementation.

