# Sources

Status: implemented

## Local And Upstream Sources

| Repository | Local reference | Upstream | Observed commit | Observed version/tag | License | Role |
| --- | --- | --- | --- | --- | --- | --- |
| ModSecurity v3 | `/root/conecter/ModSecurity_V3` | https://github.com/owasp-modsecurity/ModSecurity | `0fb4aff98b4980cf6426697d5605c424e3d5bb60` | `v3.0.15` | Apache-2.0 | Primary libmodsecurity architecture and API reference |
| ModSecurity v2 | `/root/conecter/ModSecurity_V2` | https://github.com/owasp-modsecurity/ModSecurity | `02eed22d74667b32091eece088a8ebdf64b6ba67` | `v2.9.13` | Apache-2.0 | Regression, semantics, compatibility, historical Apache reference |
| ModSecurity-apache | `/root/conecter/ModSecurity-apache` | https://github.com/owasp-modsecurity/ModSecurity-apache | `0488c77f69669584324b70460614a382224b4883` | `v0.0.9-beta1-26-g0488c77` | Apache-2.0 | Apache v3 connector reference; adapter-owned layout now lives in `connectors/apache/` with productive source in `connectors/apache/src/` |
| ModSecurity-nginx | `/root/conecter/ModSecurity-nginx` | https://github.com/owasp-modsecurity/ModSecurity-nginx | `9eb44fd9ab0988756e1ab8ce5aa5548ddbe57846` | `v1.0.4-14-g9eb44fd` | Apache-2.0 | NGINX v3 connector reference; adapter-owned layout now lives in `connectors/nginx/` with productive source in `connectors/nginx/src/` |

Local paths are workspace examples. The upstream URLs are the portable source
references for GitHub, CI, pull requests, and external maintainers.

## Public Sources

| Component | Source | Use |
| --- | --- | --- |
| HAProxy | https://docs.haproxy.org/ | Official documentation index and versioned manuals |
| HAProxy | https://github.com/haproxy/haproxy | Future connector source reference |
| HAProxy | https://raw.githubusercontent.com/haproxy/haproxy/master/doc/SPOE.txt | SPOE/SPOP architecture, events, messages, and config model |
| Envoy | https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/http/http_filters.html | HTTP filter architecture and filter ordering |
| Envoy | https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter.html | External authorization filter option |
| Envoy | https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/wasm_filter.html | Wasm filter option |
| Envoy | https://www.envoyproxy.io/docs/envoy/latest/extending/extending | Extension categories and native extension direction |
| Envoy | https://github.com/envoyproxy/envoy | Future connector source reference |
| NGINX | https://github.com/nginx/nginx | Official NGINX Open Source repository used by the NGINX PoC source-build helper |
| NGINX | https://api.github.com/repos/nginx/nginx/releases/latest | GitHub Releases API endpoint used to resolve `NGINX_RELEASE_TAG=latest` |
| NGINX | https://nginx.org/en/docs/configure.html | Official NGINX configure options used by the dynamic module build |
| Lighttpd | https://raw.githubusercontent.com/lighttpd/lighttpd1.4/master/src/plugin.h | Native plugin hook surface |
| Lighttpd | https://github.com/lighttpd/lighttpd1.4 | Future connector source reference |
| Lighttpd | https://redmine.lighttpd.net/projects/1/wiki/Docs_ModMagnet | `mod_magnet` Lua request manipulation model |
| Traefik | https://doc.traefik.io/traefik/extend/extend-traefik/ | Yaegi and Wasm plugin systems |
| Traefik | https://doc.traefik.io/traefik/master/reference/install-configuration/experimental/plugins/ | Experimental plugin configuration |
| Traefik | https://plugins.traefik.io/create | Plugin development entry point |
| Traefik | https://github.com/traefik/traefik | Future connector source reference |

No public source listed here proves that a ModSecurity connector for that
server/proxy is implemented in this repository.

## PR Evidence Sources

| Topic | Upstream PR | Local use |
| --- | --- | --- |
| RAW argument collections | https://github.com/owasp-modsecurity/ModSecurity/pull/3564 | Mapped/evidence-only until local libmodsecurity support and real Apache+NGINX PASS smokes exist |
| NGINX phase-4 / `RESPONSE_BODY` handling | https://github.com/owasp-modsecurity/ModSecurity-nginx/pull/377 | Source changes applied to adapter-owned NGINX files at commit `3d72b004ff27a78ea19c6b945870e2cae62a97ac`; `RESPONSE_BODY` remains xfail/mapped-only |
