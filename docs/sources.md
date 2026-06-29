# Sources

**Language:** English | [Deutsch](sources.de.md)

Status: implemented

## Local Sources

| Source | Observed ref | Role |
| --- | --- | --- |
| `<workspace>/ModSecurity_V3` | `v3/master`, `v3.0.15` | Primary libmodsecurity architecture and API reference |
| `<workspace>/ModSecurity_V2` | `v2/master`, `v2.9.13` | Regression, semantics, compatibility, historical Apache reference |
| `<workspace>/ModSecurity-apache` | `master`, `v0.0.9-beta1-26-g0488c77` | Apache v3 connector reference |
| `<workspace>/ModSecurity-nginx` | `master`, `v1.0.4-14-g9eb44fd` | NGINX v3 connector reference |

## Public Sources

| Component | Source | Use |
| --- | --- | --- |
| HAProxy | https://docs.haproxy.org/ | Official documentation index and versioned manuals |
| HAProxy | https://raw.githubusercontent.com/haproxy/haproxy/master/doc/SPOE.txt | SPOE/SPOP architecture, events, messages, and config model |
| Envoy | https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/http/http_filters.html | HTTP filter architecture and filter ordering |
| Envoy | https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter.html | External authorization filter option |
| Envoy | https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/wasm_filter.html | Wasm filter option |
| Envoy | https://www.envoyproxy.io/docs/envoy/latest/extending/extending | Extension categories and native extension direction |
| NGINX | https://github.com/nginx/nginx | Official NGINX Open Source repository used by the NGINX PoC source-build helper |
| NGINX | https://api.github.com/repos/nginx/nginx/releases/latest | GitHub Releases API endpoint used to resolve `NGINX_RELEASE_TAG=latest` |
| NGINX | https://nginx.org/en/docs/configure.html | Official NGINX configure options used by the dynamic module build |
| Lighttpd | https://raw.githubusercontent.com/lighttpd/lighttpd1.4/master/src/plugin.h | Native plugin hook surface |
| Lighttpd | https://redmine.lighttpd.net/projects/1/wiki/Docs_ModMagnet | `mod_magnet` Lua request manipulation model |
| Traefik | https://doc.traefik.io/traefik/extend/extend-traefik/ | Yaegi and Wasm plugin systems |
| Traefik | https://doc.traefik.io/traefik/master/reference/install-configuration/experimental/plugins/ | Experimental plugin configuration |
| Traefik | https://plugins.traefik.io/create | Plugin development entry point |

No public source listed here proves that a ModSecurity connector for that
server/proxy is implemented in this repository.
