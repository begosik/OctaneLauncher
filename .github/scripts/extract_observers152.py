"""Authenticate the passive observer and its reviewed FPS 1.0.27 fingerprints."""
from pathlib import Path
import hashlib,json,sys,zipfile
from extract_observers146 import extract,need
SHA=lambda b:hashlib.sha256(b).hexdigest()

def main():
    baseline,target,manifest,layout,out=map(Path,sys.argv[1:])
    metadata=json.loads(manifest.read_text());cfg=json.loads(layout.read_text())
    need(SHA(baseline.read_bytes())==metadata['base_zip_sha256'])
    need(SHA(target.read_bytes())==metadata['archive_sha256'])
    out.mkdir(parents=True,exist_ok=True);report={}
    for name,path in [('baseline151',baseline),('new152',target)]:
        with zipfile.ZipFile(path)as z:launcher=z.read('RA3Octane/RA3Octane.exe')
        image,report[name]=extract(launcher)
    need(report['baseline151']['sha256']=='b80ccb53b3f1c6ae454e26963faaf07ff931149a8100e0c5b560a488b6c0c380')
    need(report['new152']['sha256']==cfg['observer_sha256'])
    need(report['baseline151']['sha256']==cfg['baseline_observer_sha256'])
    need(report['new152']['bytes']==cfg['observer_bytes'])
    forbidden={'DebugActiveProcess','DebugActiveProcessStop','DebugSetProcessKillOnExit',
               'WaitForDebugEvent','WaitForDebugEventEx','ContinueDebugEvent','OpenThread',
               'SuspendThread','ResumeThread','GetThreadContext','SetThreadContext',
               'WriteProcessMemory','TerminateProcess','CreateRemoteThread','DebugBreakProcess'}
    need(not forbidden&set(report['new152']['imports']))
    need(report['new152']['imports']==report['baseline151']['imports'])
    report['scope']='Approved passive observer image with FPS127 diagnostic labels; import set matches151 and forbids debugger attachment, game-memory writes and thread control. No live RA3 execution claimed.'
    (out/'observers.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASSIVE_OBSERVER_VERIFIED',report['new152']['sha256'])

if __name__=='__main__':main()
