"""Authenticate the passive observer and its reviewed EngineLab 0.6.2 fingerprints."""
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
    for name,path in [('baseline157',baseline),('new163',target)]:
        with zipfile.ZipFile(path)as z:launcher=z.read('RA3Octane/RA3Octane.exe')
        image,report[name]=extract(launcher)
    need(report['baseline157']['sha256']=='cfb24e84af30fa2bdc9467844002878a2e84334469d4f0e59645682d5896f7b5')
    need(report['new163']['sha256']==cfg['observer_sha256'])
    need(report['baseline157']['sha256']==cfg['baseline_observer_sha256'])
    need(report['new163']['bytes']==cfg['observer_bytes'])
    forbidden={'DebugActiveProcess','DebugActiveProcessStop','DebugSetProcessKillOnExit',
               'WaitForDebugEvent','WaitForDebugEventEx','ContinueDebugEvent','OpenThread',
               'SuspendThread','ResumeThread','GetThreadContext','SetThreadContext',
               'WriteProcessMemory','TerminateProcess','CreateRemoteThread','DebugBreakProcess'}
    need(not forbidden&set(report['new163']['imports']))
    need(report['new163']['imports']==report['baseline157']['imports'])
    need(report['new163']['sha256']=='9390a5daf804b824e48c363c0d6163400f9925cc80190882e3b5cf24a5df0777')
    report['scope']='Approved passive observer image with EngineLab 0.6.2 diagnostic labels; import set matches157 and forbids debugger attachment, game-memory writes and thread control. No live RA3 execution claimed.'
    (out/'observers.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PASSIVE_OBSERVER_VERIFIED',report['new163']['sha256'])

if __name__=='__main__':main()
