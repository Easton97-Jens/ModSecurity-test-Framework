"""Check the actual generated Traefik YAML before any host starts."""
import argparse
import json
from pathlib import Path
import yaml

CONFIG_FILE = Path('/task/runtime/effective-config/traefik-forwardauth-dynamic.yaml')


def read_effective_config(path):
    if path != CONFIG_FILE or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('physical task configuration required')
    if not path.is_file() or path.stat().st_size > 65536:
        raise ValueError('bounded regular configuration required')
    return path.read_text()


def validate(text):
    value=yaml.safe_load(text)['http']
    assert set(value['routers'])=={'smoke','fault'}
    assert value['routers']['smoke']['middlewares']==['modsecurity-forwardauth','modsecurity-response-observer']
    assert value['routers']['smoke']['service']=='upstream'
    assert value['routers']['fault']['middlewares']==['modsecurity-forwardauth','observer-fault']
    assert value['routers']['fault']['rule']=='Path(`/mrc1-error`)'
    assert set(value['middlewares'])=={'modsecurity-forwardauth','modsecurity-response-observer','observer-fault'}
    auth=value['middlewares']['modsecurity-forwardauth']['forwardAuth']
    assert auth['forwardBody'] is True and auth['maxBodySize']==4096
    assert auth['maxResponseBodySize']==32768
    assert value['middlewares']['observer-fault']['plugin']['modsecurityResponseObserver']['socketPath']=='/task/sockets/fault.sock'
    assert value['services']['upstream']['loadBalancer']['servers']
    return value

if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path, choices=(CONFIG_FILE,))
    args = parser.parse_args()
    validate(read_effective_config(args.config));print(json.dumps({'yaml':'valid','routers':['smoke','fault'],'maxBodySize':4096,'maxResponseBodySize':32768}))
