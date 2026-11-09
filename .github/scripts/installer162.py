"""Run actual x86 Native162 installer with Win32 API failure injection."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess

import pefile

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--metadata', type=Path, required=True)
    parser.add_argument('--game', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--fixture-dir', type=Path, default=HERE)
    parser.add_argument('--expected-native-sha')
    args = parser.parse_args()
    native, game = args.native.resolve(), args.game.resolve()
    native_raw, game_raw = native.read_bytes(), game.read_bytes()
    native_sha = hashlib.sha256(native_raw).hexdigest()
    if args.expected_native_sha:
        assert native_sha == args.expected_native_sha
    assert hashlib.sha256(game_raw).hexdigest() == 'f1b4ede3229921abd474e0a251fe1880ca98981d9cbf45e4b5c3b8fee08c7a31'
    metadata = json.loads(args.metadata.read_text(encoding='utf-8'))
    integer = lambda x: int(x, 0) if isinstance(x, str) else x
    pe = pefile.PE(data=native_raw)
    assert hashlib.sha256(pe.get_data(0x316000, metadata['code_bytes'])).hexdigest() == metadata['code_sha256']
    terminal_rva = integer(metadata['terminal_va']) - pe.OPTIONAL_HEADER.ImageBase
    recovery_rva = integer(metadata['recovery_begin_va']) - pe.OPTIONAL_HEADER.ImageBase
    assert 0 < terminal_rva < pe.OPTIONAL_HEADER.SizeOfImage
    assert 0 < recovery_rva < pe.OPTIONAL_HEADER.SizeOfImage
    log = args.output.with_suffix('.log').resolve()
    log.parent.mkdir(parents=True, exist_ok=True)
    completed = subprocess.run([str(args.fixture_dir.resolve() / 'installer162_runner.exe'),
                                str(args.fixture_dir.resolve() / 'installer162.exe'),
                                str(native), str(game), str(log), hex(terminal_rva), hex(recovery_rva)], capture_output=True,
                               text=True, timeout=45)
    output = log.read_text(encoding='utf-8', errors='replace') if log.exists() else ''
    match = re.search(r'PASS installer_cases=(\d+) assertions=(\d+) failures=(\d+)', output)
    result = dict(passed=completed.returncode == 0 and bool(match) and match[3] == '0',
                  exit_code=completed.returncode,
                  installer_cases=int(match[1]) if match else 0,
                  assertions=int(match[2]) if match else 0,
                  native_sha256=native_sha,
                  game_sha256=hashlib.sha256(game_raw).hexdigest(), terminal_rva=hex(terminal_rva),
                  recovery_begin_rva=hex(recovery_rva),
                  real_win32_apis=['VirtualProtect', 'VirtualQuery', 'FlushInstructionCache'],
                  injected_failures=['prepare_page1..4', 'prepare_and_rollback6_scenarios',
                                     'restore_page1..4', 'flush_span1..5'],
                  instruction_span_bytes=27,
                  scope='Actual compiled NativeDLL capture/installer; authenticated game image mapped as DATA, no game entry/TLS/instructions/lobby execution. Main-module lookup, logging, co_spawn and selected Win32 failure returns isolated. Real Win32 page protections and cache flushing retained for successful calls.',
                  runner_stdout=completed.stdout, runner_stderr=completed.stderr,
                  failure_lines=[line for line in output.splitlines() if line.startswith(('FAIL', 'bad-', 'game-map-', 'load-'))])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
    if not result['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
