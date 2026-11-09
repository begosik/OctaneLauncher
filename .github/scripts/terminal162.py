"""Actual x86 terminal-guard regression with final-candidate integration support.

Usage: --native CANDIDATE --game CANONICAL --metadata MANIFEST --output JSON.
The adjacent recovery_fixture162.py is a preserved original test-code prefix,
with candidate paths supplied explicitly. No historical binary or Author-tree
dependency is needed. Explicit generation setup models reset, not SDK Begin.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import struct
import sys

import pefile

HERE = Path(__file__).resolve().parent
TERMINAL_BYTES = 30
TERMINAL_SHA = '7e1a11ad9e986e0ebcb9763e0dd392e7ad9c8ddbf5d5d29324a68e5022576623'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--game', type=Path, required=True)
    parser.add_argument('--metadata', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expected-native-sha')
    args = parser.parse_args()
    fixture = HERE / 'recovery_fixture162.py'
    if not fixture.is_file():
        fixture = HERE.parent / 'recovery_fixture162.py'
    native_raw, raw = args.native.read_bytes(), args.game.read_bytes()
    native_sha = hashlib.sha256(native_raw).hexdigest()
    if args.expected_native_sha:
        assert native_sha == args.expected_native_sha
    meta = json.loads(args.metadata.read_text(encoding='utf-8'))
    integer = lambda value: int(value, 0) if isinstance(value, str) else value
    native = pefile.PE(data=native_raw)
    assert hashlib.sha256(native.get_data(0x316000, meta['code_bytes'])).hexdigest() == meta['code_sha256']
    terminal_rva = integer(meta['terminal_va']) - native.OPTIONAL_HEADER.ImageBase
    admission_rva = integer(meta['admission_va']) - native.OPTIONAL_HEADER.ImageBase
    terminal = native.get_data(terminal_rva, TERMINAL_BYTES)
    assert hashlib.sha256(terminal).hexdigest() == TERMINAL_SHA
    args.output.parent.mkdir(parents=True, exist_ok=True)
    sys.argv = ['recovery_fixture162.py', str(args.game), str(args.native), str(args.output.parent)]
    spec = importlib.util.spec_from_file_location('terminal162_directional_fixture', fixture)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert m.HASH(raw) == m.GAME_SHA
    rows = []
    pairs = [(0, 1), (0, 6), (6, 0), (6, 7)]
    for base_index, base in enumerate([0x10000000, 0x53000000, 0x68000000]):
        relocated = pefile.PE(data=native_raw)
        relocated.relocate_image(base)
        m.NATIVE_PE = relocated
        m.NATIVE_IMAGE = relocated.get_memory_mapped_image()
        m.ADMISSION_TEST_VA = base + admission_rva
        terminal_va = base + terminal_rva
        patched = bytearray(m.guarded(raw))
        game = pefile.PE(data=raw)
        at = game.get_offset_from_rva(0xd54857 - 0x400000)
        assert raw[at:at + 5] == bytes.fromhex('8b55148910')
        patched[at:at + 5] = b'\xe9' + struct.pack('<i', terminal_va - 0xd5485c)
        image = pefile.PE(data=bytes(patched)).get_memory_mapped_image()

        def create(pair, **kwargs):
            f = m.Fixture(image, *pair, **kwargs)
            return f

        def report(f, pair, token):
            f.done = False
            for reg, value in [(m.UC_X86_REG_ESI, m.CTX), (m.UC_X86_REG_EBX, m.LOCK),
                               (m.UC_X86_REG_EDI, 0x456789ab), (m.UC_X86_REG_EBP, 0x23456789)]:
                f.u.reg_write(reg, value)
            return f.run('remote', (*pair, token))

        for pair in pairs:
            a, b = pair
            for mode in ['no_session', 'oom']:
                for matching in [True, False]:
                    f = create(pair)
                    failed = f.callback(mode)
                    assert failed['phase'] == 5 and failed['local_peer'] == failed['peer_local'] == 4
                    before_notices = len(f.notifications)
                    after = report(f, pair, m.TOKEN if matching else m.TOKEN ^ 1)
                    assert after['phase'] == 5
                    assert after['cells'][f'{a},{b}'] == after['cells'][f'{b},{a}'] == 4
                    assert len(f.notifications) == before_notices
                    assert f.sent_failed == 1 and f.sent_done == 0
                    rows.append(dict(case='late-after-failure', base=hex(base), terminal_va=hex(terminal_va),
                                     pair=pair, mode=mode, matching_token=matching, result='both_failed_no_notification'))

                # Explicitly model a fresh coordinator-owned pending generation.
                # Its setup itself is not claimed as a live scheduler/SDK test.
                f = create(pair)
                f.callback(mode)
                token = m.TOKEN ^ 0x10203040
                f.put(m.CTX + 0xbc, 1)
                f.put(m.CTX + 0x70, token)
                for x, y in [(a, b), (b, a)]:
                    f.put(m.MGR + m.state_offset(x, y), 2)
                    f.put(m.MGR + m.token_offset(x, y), token)
                f.before = bytes(f.u.mem_read(m.MGR, 0x1000))
                stale = report(f, pair, m.TOKEN)
                assert stale['phase'] == 1
                assert stale['cells'][f'{a},{b}'] == stale['cells'][f'{b},{a}'] == 2
                current = report(f, pair, token)
                assert current['phase'] == 1
                assert current['cells'][f'{a},{b}'] == 3 and current['cells'][f'{b},{a}'] == 2
                duplicate = report(f, pair, token)
                assert duplicate['phase'] == 1
                assert duplicate['cells'][f'{a},{b}'] == 3 and duplicate['cells'][f'{b},{a}'] == 2
                success = f.callback('success_stub')
                assert success['phase'] == 4 and success['local_peer'] == success['peer_local'] == 3
                rows.append(dict(case='fresh-generation', base=hex(base), terminal_va=hex(terminal_va),
                                 pair=pair, previous_mode=mode, old_report_refused=True,
                                 fresh_report_allowed=True, duplicate_idempotent=True,
                                 local_admission_success_stubbed=True, result='both_connected'))

            # Preserve the canonical setter's own token guard, independently
            # of the receive handler's current-context token comparison.
            f = create(pair, matrix_token=m.TOKEN ^ 1)
            for x, y in [(a, b), (b, a)]:
                f.put(m.MGR + m.state_offset(x, y), 4)
            f.before = bytes(f.u.mem_read(m.MGR, 0x1000))
            after = report(f, pair, m.TOKEN)
            assert after['cells'][f'{a},{b}'] == after['cells'][f'{b},{a}'] == 4
            assert f.notifications == []
            rows.append(dict(case='canonical-stored-token-mismatch', base=hex(base), pair=pair,
                             result='unchanged_no_notification'))

            # Execute the complete canonical setter for each state transition.
            # A real reset 4->1/2 remains allowed; only 4->3 is suppressed.
            for previous in [1, 2, 3, 4]:
                for requested in [1, 2, 3, 4]:
                    f = create(pair)
                    target = m.MGR + m.state_offset(a, b)
                    f.put(target, previous)
                    trace = []
                    def flags_trace(u, pc, _size, _):
                        if pc in [terminal_va, 0xd5485c, 0xd54867]:
                            trace.append((pc, u.reg_read(m.UC_X86_REG_EFLAGS),
                                          u.reg_read(m.UC_X86_REG_ESP)))
                    f.u.hook_add(m.UC_HOOK_CODE, flags_trace)
                    for i, value in enumerate([m.SENTINEL, a, b, m.TOKEN, requested]):
                        f.put(m.STACK + 4 * i, value)
                    f.u.reg_write(m.UC_X86_REG_ESP, m.STACK)
                    f.u.reg_write(m.UC_X86_REG_ECX, m.MGR)
                    f.u.emu_start(0x687070, 0x1400000, count=10000)
                    refused = previous == 4 and requested == 3
                    assert f.done
                    assert f.get(target) == (previous if refused else requested)
                    assert len(f.notifications) == (0 if refused else 1)
                    assert f.u.reg_read(m.UC_X86_REG_ESP) == m.STACK + 20
                    for reg, value in [(m.UC_X86_REG_ESI, m.CTX), (m.UC_X86_REG_EBX, m.LOCK),
                                       (m.UC_X86_REG_EDI, 0x456789ab), (m.UC_X86_REG_EBP, 0x23456789)]:
                        assert f.u.reg_read(reg) == value
                    assert trace[0][0] == terminal_va
                    assert trace[1][0] == (0xd54867 if refused else 0xd5485c)
                    assert trace[0][1:] == trace[1][1:]
                    rows.append(dict(case='canonical-setter-transition', base=hex(base), pair=pair,
                                     previous=previous, requested=requested, refused=refused,
                                     guard_flags_stack_preserved=True, setter_callee_saved_preserved=True))

    result = dict(passed=True, cases=len(rows), bases=3,
                  late_failure_cases=48, fresh_generation_cases=24,
                  stored_token_mismatch_cases=12, setter_transition_cases=192,
                  actual_native_sha256=native_sha,
                  candidate_bound=True, terminal_rva=hex(terminal_rva),
                  game_sha256=hashlib.sha256(raw).hexdigest(),
                  terminal_code_sha256=TERMINAL_SHA,
                  scope='Actual x86 reviewed game completion paths, 6+2 setter and compiled terminal guard. Original admission failure functions retained, OOM allocator injected; successful admission stubbed. Explicit pending/token setup models a new generation, not SDK Begin. Locks/UI/reports/diagnostics isolated. No live lobby or network.',
                  rows=rows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: result[k] for k in ['passed', 'cases', 'late_failure_cases',
                                          'fresh_generation_cases', 'stored_token_mismatch_cases',
                                          'setter_transition_cases', 'candidate_bound', 'scope']}, indent=2))


if __name__ == '__main__':
    main()
