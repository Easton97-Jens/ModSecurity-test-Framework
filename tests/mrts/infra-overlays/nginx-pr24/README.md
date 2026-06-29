# NGINX PR24 MRTS Overlay

**Language:** English | [Deutsch](README.de.md)

This overlay is copied from the open MRTS PR 24 `config_infra/nginx_linux/`
tree. It is framework-owned temporary infrastructure for native MRTS NGINX
evidence and is staged under `MRTS_NATIVE_ROOT` before use.

Runtime scripts must patch only the staged copy. Do not edit `tools/MRTS` or
the copied overlay files to make runtime results pass.

Replace this overlay with `$MRTS_ROOT/config_infra/nginx_linux` once PR 24 is
merged upstream.
