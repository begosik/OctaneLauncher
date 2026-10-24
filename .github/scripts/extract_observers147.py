"""Authenticate that147 retains the exact passive observer from public146."""
from pathlib import Path
import hashlib,json,sys,zipfile
from extract_observers146 import extract,need
SHA=lambda b:hashlib.sha256(b).hexdigest()
def main():
 baseline,target,manifest,out=map(Path,sys.argv[1:]);m=json.loads(manifest.read_text())
 need(SHA(baseline.read_bytes())==m['base_zip_sha256']and SHA(target.read_bytes())==m['archive_sha256'])
 out.mkdir(parents=True,exist_ok=True);report={};images={}
 for name,path in [('baseline146',baseline),('new147',target)]:
  with zipfile.ZipFile(path)as z:exe=z.read('RA3Octane/RA3Octane.exe')
  images[name],report[name]=extract(exe)
 need(images['baseline146']==images['new147'])
 need(SHA(images['new147'])=='06287fe6fcf87fe3d4205c28ceca3a1d11175483ec86524a4ab3f82842d27ef1')
 forbidden={'DebugActiveProcess','DebugActiveProcessStop','DebugSetProcessKillOnExit','WaitForDebugEvent','WaitForDebugEventEx','ContinueDebugEvent','OpenThread','SuspendThread','ResumeThread','GetThreadContext','SetThreadContext','WriteProcessMemory','TerminateProcess','CreateRemoteThread','DebugBreakProcess'}
 need(not forbidden&set(report['new147']['imports']))
 (out/'observers.json').write_text(json.dumps(report,indent=2)+'\n')
 print('UNCHANGED_PASSIVE_OBSERVER_VERIFIED',report['new147']['sha256'])
if __name__=='__main__':main()
