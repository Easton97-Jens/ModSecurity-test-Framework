#!/bin/sh
# Execute only the inventoried pinned-CRS profile, never a catalog discovery.
set -eu
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
CONNECTOR_ROOT=${CONNECTOR_ROOT:?CONNECTOR_ROOT is required explicitly}
connector=${1:?an inventoried connector is required}
case "$connector" in
    apache|haproxy)
        exec make -C "$CONNECTOR_ROOT" "verified-$connector-case" \
            CASE=crs_sqli_anomaly_block CRS=with-crs MRTS=no-mrts
        ;;
    envoy|traefik|lighttpd)
        : "${CRS_RUNTIME_RUN_ID:?the workflow must bind its private runtime run ID}"
        exec sh "$SCRIPT_DIR/run-with-crs-no-mrts.sh" "$connector" "$CRS_RUNTIME_RUN_ID"
        ;;
    *) echo "FAIL: connector is not in the active CRS inventory" >&2; exit 2 ;;
esac
