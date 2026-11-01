/* Framework-only fault-injection state for the native listener ownership regression. */
#ifndef MSCONNECTOR_FRAMEWORK_TRAEFIK_ENGINE_TEST_HOOKS_H
#define MSCONNECTOR_FRAMEWORK_TRAEFIK_ENGINE_TEST_HOOKS_H

typedef int (*traefik_engine_listener_pre_bind_hook_fn)(const char *socket_path);

static traefik_engine_listener_pre_bind_hook_fn
    traefik_engine_listener_pre_bind_hook = 0;
static traefik_engine_listener_pre_bind_hook_fn
    traefik_engine_listener_post_bind_hook = 0;
static traefik_engine_listener_pre_bind_hook_fn
    traefik_engine_listener_post_probe_hook = 0;

#define TRAEFIK_ENGINE_LISTENER_PRE_BIND_CHECK(path) (traefik_engine_listener_pre_bind_hook == 0 || traefik_engine_listener_pre_bind_hook(path))
#define TRAEFIK_ENGINE_LISTENER_POST_BIND_CHECK(path) (traefik_engine_listener_post_bind_hook == 0 || traefik_engine_listener_post_bind_hook(path))
#define TRAEFIK_ENGINE_LISTENER_POST_PROBE_CHECK(path) (traefik_engine_listener_post_probe_hook == 0 || traefik_engine_listener_post_probe_hook(path))

#endif
