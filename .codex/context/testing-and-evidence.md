# Framework Testing and Evidence Delta

## Layers

Keep these evidence classes distinct:

1. static/schema/documentation checks;
2. catalog/selection checks;
3. starter/build/self-test prerequisites;
4. real connector runtime smoke/evidence;
5. generated reports and aggregate views.

A success in one class does not imply success in a later class.

## Status truth

Use repository-native status semantics. `PASS` and `FAIL` describe observed results. `BLOCKED` is an unmet prerequisite. `NOT_EXECUTABLE` is a structural non-executability result. Neither blocker class is a PASS.

## Host evidence boundary

Framework output cannot promote P1-P4, RESPONSE_BODY, protocol coverage, production readiness, first-byte behavior, strict late intervention, or connector support without the connector-owned evidence required by the current contract.

## Commands

Select commands from the current Framework `Makefile` and maintained docs. Run the smallest focused check first, then the relevant repository-level checks. RTK wrapping remains mandatory under inherited `PARENT-COMMAND-EXECUTION`.

## Generated artifacts

Generated reports are changed only through their generator. Keep build/runtime/evidence artifacts outside the Git worktree using the active Framework configuration roots.
