#!/usr/bin/env python3
from modsecurity_test_framework.connector_context import connector_root, test_root, source_path, load_tool
from pathlib import Path
import sys
ROOT=connector_root()
mk=(test_root()/'connector_suite/connector.mk').read_text()
haproxy_mk=(source_path('connectors/haproxy/Makefile', root=ROOT)).read_text()
sh=source_path('ci/checks/connectors/haproxy/check-haproxy-c-standards.sh', root=ROOT)
ok=True
def check(cond,msg):
 global ok
 print(('PASS' if cond else 'FAIL')+': '+msg)
 ok = ok and cond
check(sh.exists(),'ci/checks/connectors/haproxy/check-haproxy-c-standards.sh exists')
for target in ['check-haproxy-c17','check-haproxy-c23','check-haproxy-future-c','check-haproxy-c-standards','check-haproxy-c17-lint']:
 check((target+':') in mk, f'Makefile contains {target}')
check('$(MAKE) check-haproxy-c17-lint' in mk, 'lint invokes check-haproxy-c17-lint')
txt=''
if sh.exists():
 txt=sh.read_text()
 check('-Wno-error' not in txt, 'script does not disable -Werror')
 check('-std=c17' in txt, 'C17 is mandatory')
 check('c23' in txt and 'c2y' in txt and 'SKIPPED' in txt and 'exit 77' in txt, 'optional C23/future-C skip behavior is present')
 check('FRAMEWORK_COMMON' in txt and 'require_or_provision_haproxy_headers' in txt, 'script uses framework common HAProxy header provision helper')
 check('require_command_or_blocked' in txt, 'script uses framework common command blocker helper')
 check('modsecurity_include_flags_or_provision' in txt, 'script uses framework common libmodsecurity header provision helper')
 check('common/src/transaction_state.c' in txt, 'script compiles Common transaction_state.c')
 check('probe_haproxy_headers' in txt and 'haproxy/api.h' in txt and 'missing usable HAProxy headers/source' in txt, 'script probes actual HAProxy headers before passing')
check('COMMON_CPPFLAGS := -I$(COMMON_INCLUDE)' in haproxy_mk, 'HAProxy Makefile defines Common include compile flags')
check('$(CC) $(CPPFLAGS) $(COMMON_CPPFLAGS) $(CFLAGS)' in haproxy_mk, 'HAProxy Makefile compiles Common-linked sources with Common include flags')
check('src/haproxy_modsecurity_mapper.c $(COMMON_SDK_SRCS)' in haproxy_mk and '$(CXX) $(LDFLAGS)' in haproxy_mk and 'src/haproxy_modsecurity_mapper.c $(COMMON_SDK_SRCS) -L' not in haproxy_mk, 'Common sources are compiled to objects before link')
for src in ['http_status.c','block_statuses.c','path_policy.c','intervention.c','transaction_state.c','late_intervention.c','decision_action.c','rule_error.c','rule_event.c','rule_merge.c','artifacts.c','artifact_layout.c','test_result.c','test_result_json.c']:
 if src in {'test_result.c','test_result_json.c'}:
  check('for f in common/src/test_result.c common/src/test_result_json.c; do' in txt
        and 'src="$TEST_ROOT/connector_suite/$f"' in txt
        and '-I"$TEST_ROOT/connector_suite/common/include" $incs -c "$src"' in txt
        and 'missing listed Framework source' in txt and 'return 1' in txt,
        f'Framework standards compile includes required {src}')
 else:
  check(f'$(COMMON_SRC)/{src}' in haproxy_mk, f'COMMON_SDK_SRCS includes {src}')
sys.exit(0 if ok else 1)
