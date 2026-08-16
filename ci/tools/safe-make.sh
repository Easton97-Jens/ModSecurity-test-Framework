#!/bin/sh
# Execute the Framework's top-level GNU Make with inherited Make control-plane
# inputs removed.  GNU Make consumes these variables before reading a
# Makefile, so recipe-level validation is too late for this boundary.
set -eu

SCRIPT_PATH=$0
case $SCRIPT_PATH in
    /*) ;;
    *) SCRIPT_PATH=$PWD/$SCRIPT_PATH ;;
esac
SCRIPT_DIR=${SCRIPT_PATH%/*}
[ "$SCRIPT_DIR" = "$SCRIPT_PATH" ] && SCRIPT_DIR=.
SCRIPT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR" && pwd)
FRAMEWORK_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

if [ -x /usr/bin/make ]; then
    TRUSTED_MAKE=/usr/bin/make
elif [ -x /bin/make ]; then
    TRUSTED_MAKE=/bin/make
else
    echo "safe-make: trusted GNU Make not found" >&2
    exit 77
fi

# MAKEFLAGS/GNUMAKEFLAGS can inject --eval/--include before the Makefile;
# MAKEFILES and MAKEOVERRIDES can force extra files or recursive overrides.
unset MAKE MAKEFLAGS GNUMAKEFLAGS MAKEFILES MAKEOVERRIDES MFLAGS MAKELEVEL

for argument in "$@"; do
    case $argument in
        MAKE*=*|GNUMAKEFLAGS*=*|MAKEFILES*=*|MAKEOVERRIDES*=*|MFLAGS*=*|MAKELEVEL*=*|SHELL*=*|MAKEFILE_LIST*=*)
            echo "safe-make: Make control-variable assignments are not accepted in arguments" >&2
            exit 77
            ;;
        -E|--eval|--eval=*|-f|--file|--file=*|--makefile|--makefile=*|-C|--directory|--directory=*|-I|--include-dir|--include-dir=*)
            echo "safe-make: Make source/evaluation options are not accepted" >&2
            exit 77
            ;;
        -E*|-f*|-C*|-I*)
            echo "safe-make: Make source/directory options are not accepted" >&2
            exit 77
            ;;
        -e|--environment-overrides)
            echo "safe-make: environment Make overrides are not accepted" >&2
            exit 77
            ;;
        *)
            :
            ;;
    esac
done

cd "$FRAMEWORK_ROOT"
exec "$TRUSTED_MAKE" "$@"
