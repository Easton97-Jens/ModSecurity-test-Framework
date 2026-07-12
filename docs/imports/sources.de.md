# Quellen

**Sprache:** [English](sources.md) | Deutsch

Status: umgesetzt

## Lokale und vorgelagerte Quellen

| Repository | Lokaler Bezug | Stromaufwärts | Beobachteter Commit | Beobachtet version/tag | Lizenz | Rolle |
| --- | --- | --- | --- | --- | --- | --- |
| ModSecurity v3 | `<workspace>/ModSecurity_V3` | https://github.com/owasp-modsecurity/ModSecurity | `0fb4aff98b4980cf6426697d5605c424e3d5bb60` | `v3.0.15` | Apache-2.0 | Primäre libmodsecurity-Architektur und API-Referenz |
| ModSecurity v2 | `<workspace>/ModSecurity_V2` | https://github.com/owasp-modsecurity/ModSecurity | `02eed22d74667b32091eece088a8ebdf64b6ba67` | `v2.9.13` | Apache-2.0 | Regression, Semantik, Kompatibilität, historische Apache-Referenz |
| ModSecurity-Apache | `<workspace>/ModSecurity-apache` | https://github.com/owasp-modsecurity/ModSecurity-apache | `0488c77f69669584324b70460614a382224b4883` | `v0.0.9-beta1-26-g0488c77` | Apache-2.0 | Referenz zum Apache v3-Connector; Adaptereigenes Layout befindet sich jetzt in `connectors/apache/` mit produktiver Quelle in `connectors/apache/src/` |
| ModSecurity-nginx | `<workspace>/ModSecurity-nginx` | https://github.com/owasp-modsecurity/ModSecurity-nginx | `9eb44fd9ab0988756e1ab8ce5aa5548ddbe57846` | `v1.0.4-14-g9eb44fd` | Apache-2.0 | NGINX v3-Connector-Referenz; Adaptereigenes Layout befindet sich jetzt in `connectors/nginx/` mit produktiver Quelle in `connectors/nginx/src/` |

Lokale Pfade sind Beispiele für Arbeitsbereiche. Die Upstream-URLs sind die portable Quelle
Referenzen für GitHub, CI, Pull Requests und externe Betreuer.

## Öffentliche Quellen

| Komponente | Quelle | Benutzen |
| --- | --- | --- |
| HAProxy | https://docs.haproxy.org/ | Offizieller Dokumentationsindex und versionierte Handbücher |
| HAProxy | https://github.com/haproxy/haproxy | Zukünftige Connector-Quellenreferenz |
| HAProxy | https://raw.githubusercontent.com/haproxy/haproxy/master/doc/SPOE.txt | SPOE/SPOP Architektur, Ereignisse, Nachrichten und Konfigurationsmodell |
| Gesandter | https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/http/http_filters.html | HTTP Filterarchitektur und Filterreihenfolge |
| Gesandter | https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter.html | Externe Autorisierungsfilteroption |
| Gesandter | https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/wasm_filter.html | Wasm-Filteroption |
| Gesandter | https://www.envoyproxy.io/docs/envoy/latest/extending/extending | Erweiterungskategorien und native Erweiterungsrichtung |
| Gesandter | https://github.com/envoyproxy/envoy | Zukünftige Connector-Quellenreferenz |
| NGINX | https://github.com/nginx/nginx | Offizielles NGINX Open-Source-Repository, das vom NGINX PoC-Source-Build-Helfer verwendet wird |
| NGINX | https://api.github.com/repos/nginx/nginx/releases/latest | GitHub veröffentlicht den API-Endpunkt, der zum Auflösen von `NGINX_RELEASE_TAG=latest` verwendet wird |
| NGINX | https://nginx.org/en/docs/configure.html | Offizielle NGINX Konfigurationsoptionen, die vom dynamischen Modul-Build verwendet werden |
| Lighttpd | https://raw.githubusercontent.com/lighttpd/lighttpd1.4/master/src/plugin.h | Native Plugin-Hook-Oberfläche |
| Lighttpd | https://github.com/lighttpd/lighttpd1.4 | Zukünftige Connector-Quellenreferenz |
| Lighttpd | https://redmine.lighttpd.net/projects/1/wiki/Docs_ModMagnet | `mod_magnet` Lua-Anforderungsmanipulationsmodell |
| Traefik | https://doc.traefik.io/traefik/extend/extend-traefik/ | Yaegi- und Wasm-Plugin-Systeme |
| Traefik | https://doc.traefik.io/traefik/master/reference/install-configuration/experimental/plugins/ | Experimentelle Plugin-Konfiguration |
| Traefik | https://plugins.traefik.io/create | Einstiegspunkt für die Plugin-Entwicklung |
| Traefik | https://github.com/traefik/traefik | Zukünftige Connector-Quellenreferenz |

Keine hier aufgeführte öffentliche Quelle beweist, dass es dafür einen ModSecurity-Connector gibt
server/proxy ist in diesem Repository implementiert.

## PR Nachweisquellen

| Thema | Upstream PR | Lokale Verwendung |
| --- | --- | --- |
| RAW Argumentsammlungen | https://github.com/owasp-modsecurity/ModSecurity/pull/3564 | Mapped/evidence-only bis lokale libmodsecurity-Unterstützung und echte Apache+NGINX PASS Smokes vorhanden sind |
| NGINX Phase-4 / `RESPONSE_BODY` Behandlung | https://github.com/owasp-modsecurity/ModSecurity-nginx/pull/377 | Quelländerungen, die beim Commit `3d72b004ff27a78ea19c6b945870e2cae62a97ac` auf Adapter-eigene NGINX-Dateien angewendet werden; `RESPONSE_BODY` bleibt ehemaliger expected-failure/mapped-only |
