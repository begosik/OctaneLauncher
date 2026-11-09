"""Run the isolated x86 Native162 connection/endpoint regression fixture.

Only loopback UDP is permitted by the native harness. Full relay registration,
UI/game execution and the live speed worker are outside this test.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess

HERE=Path(__file__).resolve().parent


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('native',type=Path)
    parser.add_argument('--fixture',type=Path,default=HERE/'connection162_fixture.exe')
    parser.add_argument('--native-sha256')
    parser.add_argument('--metadata',type=Path)
    parser.add_argument('--output',type=Path,default=HERE/'connection162_results.json')
    args=parser.parse_args()
    native=args.native.resolve();fixture=args.fixture.resolve();output=args.output.resolve()
    digest=hashlib.sha256(native.read_bytes()).hexdigest()
    if args.native_sha256 and digest!=args.native_sha256.lower():
        raise SystemExit('Native fixture hash mismatch')
    output.parent.mkdir(parents=True,exist_ok=True)
    metadata=None;current_rva=endpoint_rva=None;state_struct_bytes=2636
    if args.metadata:
        metadata=json.loads(args.metadata.read_text(encoding='utf-8'))
        integer=lambda value: int(value,0) if isinstance(value,str) else int(value)
        symbols=metadata.get('symbols',{})
        current=symbols.get('_relay_connection_current',metadata.get('relay_connection_current_rva'))
        endpoint=symbols.get('_endpoint162_on_local_receive',metadata.get('endpoint162_on_local_receive_rva'))
        if current is None or endpoint is None:raise SystemExit('Explicit registry and endpoint helper metadata required')
        current_rva=integer(current);endpoint_rva=integer(endpoint)
        if current_rva>=0x10000000:current_rva-=0x10000000
        if endpoint_rva>=0x10000000:endpoint_rva-=0x10000000
        if not (0x316000<=current_rva<0x400000 and 0x316000<=endpoint_rva<0x400000):raise SystemExit('Invalid bounded helper RVA metadata')
        state_struct_bytes=integer(metadata.get('state_struct_bytes',metadata.get('state_structure_bytes',2636)))
        if not 2636<=state_struct_bytes<0xb00:raise SystemExit('Invalid state structure size')
    rows=[]
    modes=['matrix','late','cache','tiny']+(['churn'] if metadata else [])
    for mode in modes:
        command=[str(fixture),str(native)]+([mode] if mode!='matrix' else [])
        if mode=='churn':command += [hex(current_rva),hex(endpoint_rva),str(state_struct_bytes)]
        try:
            completed=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=35)
            raw=completed.stdout;code=completed.returncode;failure=None
        except subprocess.TimeoutExpired as error:
            raw=error.stdout or b'';code=-1;failure='owned fixture exceeded35second timeout'
        log=output.with_name(output.stem+'_'+mode+'.log');log.write_bytes(raw)
        text=raw.decode('utf-8',errors='replace')
        summary=[line for line in text.splitlines() if line.startswith(('loaded=','initial_bidirectional','idle_probe','changed_source','endpoint162','late_ctor','cache162','registry162','remote162','FAIL','exception='))]
        if mode=='matrix':
            required=['unregistered-port','wrong-session-seq0','authorized-current-seq0','superseded-owner','unregistered-owner']
            checks=all('endpoint162_case='+name+' expected_destination=1 forbidden_destination=0' in text for name in required)
            checks=checks and 'endpoint162_matrix=PASS fixed_expected=1 blocked_remote=0' in text
        elif mode=='late':
            checks='endpoint162_late_ctor expected_fresh=1 expected_destination=1 forbidden_destination=0' in text and 'late_ctor_mode=PASS blocked_remote=0' in text
        elif mode=='cache':
            checks=bool(re.search(r'cache162_natural_expiry original_cache_absent=1 same_live_registry_port=[1-9][0-9]* registration_bypassed=1',text))
            checks=checks and bool(re.search(r'cache162_old_destructor newer_owner_port_preserved=[1-9][0-9]*',text))
            checks=checks and 'cache162_current_destructor cached_port_invalidated=1 old_owner_not_revived=1' in text and 'cache162_mode=PASS blocked_remote=0' in text
        elif mode=='tiny':
            checks='remote162_tiny drop_zero=1 drop_one=1 endpoint_unchanged=1 watchdog_unchanged=1 no_game_datagrams=1' in text
            checks=checks and 'remote162_tiny later_bidirectional_payload=PASS idle_probe_reply=PASS' in text and 'remote162_tiny_mode=PASS blocked_remote=0' in text
        else:
            checks='registry162_churn real_constructors=66 bound=64 observed_max=64 recent_owner_retained=1 newest_tracked=1 evicted_owner_rejected=1 evicted_endpoint_unchanged=1' in text
            checks=checks and ('registry162_churn sockets_still_open_before_cleanup=132 unused_state_tail_bytes='+str(0xb00-state_struct_bytes)+' canary=PASS cleanup_live_records=1') in text
            checks=checks and 'registry162_churn_mode=PASS blocked_remote=0' in text
        passed=code==0 and checks and 'FAIL ' not in text
        rows.append(dict(mode=mode,passed=passed,exit_code=code,failure=failure,log=log.name,summary=summary))
        print('CONNECTION162',mode,'PASS' if passed else 'FAIL')
    result=dict(passed=all(row['passed'] for row in rows),native_sha256=digest,
                fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
                processes=len(rows),named_checks=10+bool(metadata),large_packet_buffers_tested_or_changed=False,
                metadata_sha256=hashlib.sha256(args.metadata.read_bytes()).hexdigest() if metadata else None,
                registry_current_rva=hex(current_rva) if metadata else None,endpoint_receive_rva=hex(endpoint_rva) if metadata else None,state_struct_bytes=state_struct_bytes if metadata else None,
                full_external_registration_executed=False,live_game_or_lobby_executed=False,
                scope='Actual x86 NativeDll Connection constructors/destructors, local/remote Asio UDP forwarding, endpoint/lifecycle bridges, original cache-watchdog expiry and local NATNEG INIT1 dispatcher. Loopback only. The fixture forces current/superseded ownership with real extra constructors/destructors and explicitly seeds the original cache port when checking destructor invalidation. Zero/one-byte remote datagrams are also checked before endpoint learning/watchdog/header parsing, with the original continue cleanup instrumented only as a completion observer; later idle probe and bidirectional payload forwarding execute. With explicit metadata, a fifth mode constructs66real Connections, checks64entry LRU/current-owner behavior,132unclosed sockets before cleanup, evicted-owner endpoint rejection and an unused-state-tail canary. Only the receive frame/seq0membership are seeded for that extra rejection check. The original speed worker and game-facing metrics/telemetry are isolated. No game entry point, SDK handshake, UI, live lobby/match, VPN transition or full external relay registration.',cases=rows)
    output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    if not result['passed']:raise SystemExit(1)


if __name__=='__main__':main()
