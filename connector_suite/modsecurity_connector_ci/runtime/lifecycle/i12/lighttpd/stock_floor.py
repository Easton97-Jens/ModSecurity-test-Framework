"""Run the existing syscall fault seam against actual Stock default reserve."""
import argparse
import json
from pathlib import Path
import subprocess

from modsecurity_connector_ci.runtime.lifecycle.i12.lighttpd.stock_qualification import EXTERNAL, REPO, regular, sha


def capture(output):
    output = Path(output).absolute()
    if '..' in output.parts or not output.is_relative_to(EXTERNAL):
        raise ValueError('external task output required')
    if any(path.is_symlink() for path in (*output.parents, output)):
        raise ValueError('output aliases forbidden')
    output.mkdir(mode=0o700, parents=True)
    source = regular(Path(__file__).with_name('stock_spool_floor.c'))
    product = regular(REPO / 'connectors/lighttpd/stock_sidecar/stock_sidecar.c')
    binary = output / 'stock-floor'
    command = ['rtk', 'proxy', 'cc', '-std=c17', '-Wall', '-Wextra', '-Werror',
        '-ffunction-sections', '-fdata-sections', '-pthread', '-I.', '-Icommon/include',
        '-Icommon/runtime', '-Iconnectors/lighttpd/stock_sidecar',
        str(source),
        '-Wl,--gc-sections', '-lcrypto', '-o', str(binary)]
    compiled = subprocess.run(command, cwd=REPO, capture_output=True, text=True, timeout=60)
    (output / 'compile.stdout').write_text(compiled.stdout)
    (output / 'compile.stderr').write_text(compiled.stderr)
    receipt = {'layer': 'injected-existing-syscall-seam', 'compile_argv': command,
        'compile_exit': compiled.returncode, 'source': {'path': str(source), 'sha256': sha(source)},
        'unchanged_product_source': {'path': str(product), 'sha256': sha(product)},
        'host_disk_exhausted': False}
    if compiled.returncode == 0:
        run = ['rtk', 'proxy', str(binary), str(output)]
        result = subprocess.run(run, capture_output=True, text=True, timeout=15)
        (output / 'run.stdout').write_text(result.stdout)
        (output / 'run.stderr').write_text(result.stderr)
        receipt.update(run_argv=run, run_exit=result.returncode, binary_sha256=sha(binary))
        if result.returncode == 0:
            receipt['actual_assertion_receipt'] = json.loads(result.stdout)
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(capture(args.output), indent=2))
