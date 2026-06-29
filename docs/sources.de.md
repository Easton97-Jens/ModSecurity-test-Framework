# Quellen

**Sprache:** [English](sources.md) | Deutsch

Status: umgesetzt

## Lokale Quellen

| Quelle | Beobachtete Referenz | Rolle |
| --- | --- | --- |
| `<workspace>/ModSecurity_V3` | `v3/master`, `v3.0.15` | Primäre libmodsecurity-Architektur und API-Referenz |
| `<workspace>/ModSecurity_V2` | `v2/master`, `v2.9.13` | Regression, Semantik, Kompatibilität, historische Apache-Referenz |
| `<workspace>/ModSecurity-apache` | `master`, `v0.0.9-beta1-26-g0488c77` | Referenz zum Apache v3-Connector |
| `<workspace>/ModSecurity-nginx` | `master`, `v1.0.4-14-g9eb44fd` | NGINX v3-Connector-Referenz |

## Öffentliche Quellen

| Komponente | Quelle | Benutzen |
| --- | --- | --- |
| HAProxy | https://docs.haproxy.org/ | Offizieller Dokumentationsindex und versionierte Handbücher |
| HAProxy | https://raw.githubusercontent.com/haproxy/haproxy/master/doc/SPOE.txt | SPOE/SPOP Architektur, Ereignisse, Nachrichten und Konfigurationsmodell |
| Gesandter | https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/http/http_filters.html | HTTP Filterarchitektur und Filterreihenfolge |
| Gesandter | https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter.html | Externe Autorisierungsfilteroption |
| Gesandter | https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/wasm_filter.html | Wasm-Filteroption |
| Gesandter | https://www.envoyproxy.io/docs/envoy/latest/extending/extending | Erweiterungskategorien und native Erweiterungsrichtung |
| NGINX | https://github.com/nginx/nginx | Offizielles NGINX Open-Source-Repository, das vom NGINX PoC-Source-Build-Helfer verwendet wird |
| NGINX | https://api.github.com/repos/nginx/nginx/releases/latest | GitHub veröffentlicht den API-Endpunkt, der zum Auflösen von `NGINX_RELEASE_TAG=latest` verwendet wird |
| NGINX | https://nginx.org/en/docs/configure.html | Offizielle NGINX Konfigurationsoptionen, die vom dynamischen Modul-Build verwendet werden |
| Lighttpd | https://raw.githubusercontent.com/lighttpd/lighttpd1.4/master/src/plugin.h | Native Plugin-Hook-Oberfläche |
| Lighttpd | https://redmine.lighttpd.net/projects/1/wiki/Docs_ModMagnet | `mod_magnet` Lua-Anforderungsmanipulationsmodell |
| Traefik | https://doc.traefik.io/traefik/extend/extend-traefik/ | Yaegi- und Wasm-Plugin-Systeme |
| Traefik | https://doc.traefik.io/traefik/master/reference/install-configuration/experimental/plugins/ | Experimentelle Plugin-Konfiguration |
| Traefik | https://plugins.traefik.io/create | Einstiegspunkt für die Plugin-Entwicklung |

Keine hier aufgeführte öffentliche Quelle beweist, dass es dafür einen ModSecurity-Connector gibt
server/proxy ist in diesem Repository implementiert.
