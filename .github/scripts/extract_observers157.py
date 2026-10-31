"""Authenticate the passive observer and its reviewed FPS 1.0.36 fingerprints."""
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
    for name,path in [('baseline156',baseline),('new157',target)]:
        with zipfile.ZipFile(path)as z:launcher=z.read('RA3Octane/RA3Octane.exe')
        image,report[name]=extract(launcher)
    need(report['baseline156']['sha256']=='4adad00a5f49bbddb3de465946124a93b4a03b35c8158b522c2a0e52019ba5ad')
    need(report['new157']['sha256']==cfg['observer_sha256'])
    need(report['baseline156']['sha256']==cfg['baseline_observer_sha256'])
    need(report['new157']['bytes']==cfg['observer_bytes'])
    forbidden={'DebugActiveProcess','DebugActiveProcessStop','DebugSetProcessKillOnExit',
               'WaitForDebugEvent','WaitForDebugEventEx','ContinueDebugEvent','OpenThread',
               'SuspendThread','ResumeThread','GetThreadContext','SetThreadContext',
               'WriteProcessMemory','TerminateProcess','CreateRemoteThread','DebugBreakProcess'}
    need(not forbidden&set(report['new157']['imports']))
    need(report['new157']['imports']==report['baseline156']['imports'])
    report['scope']='Approved passive observer image with FPS136 diagnostic labels; import set matches156 and forbids debugger attachment, game-memory writes and thread control. No live RA3 execution claimed.'
    (out/'observers.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASSIVE_OBSERVER_VERIFIED',report['new157']['sha256'])

if __name__=='__main__':main()
