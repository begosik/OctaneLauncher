"""Verify the actual signed launcher's execution-level contract without running it."""
from pathlib import Path
import hashlib,json,sys,zipfile
import xml.etree.ElementTree as ET
import pefile

def check_package(package):
    with zipfile.ZipFile(package) as z:
        assert z.testzip() is None
        exe=z.read('RA3Octane/RA3Octane.exe')
    pe=pefile.PE(data=exe)
    manifests=[]
    for typ in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if typ.id != 24:
            continue
        for name in typ.directory.entries:
            for lang in name.directory.entries:
                data=lang.data.struct
                manifests.append(pe.get_data(data.OffsetToData,data.Size))
    assert manifests,'Launcher manifest missing'
    levels=[]
    for manifest in manifests:
        tree=ET.fromstring(manifest)
        levels += [n.attrib.get('level') for n in tree.iter() if n.tag.rsplit('}',1)[-1]=='requestedExecutionLevel']
    assert levels == ['asInvoker'],levels
    imports={row.name.decode('ascii') for dll in pe.DIRECTORY_ENTRY_IMPORT for row in dll.imports if row.name}
    forbidden={'CreateProcessAsUserA','CreateProcessAsUserW','CreateProcessWithTokenW',
               'CreateProcessWithLogonW','SetThreadToken','ImpersonateLoggedOnUser'}
    assert not imports & forbidden,imports & forbidden
    assert 'CreateProcessW' in imports and 'ShellExecuteExW' in imports
    return {'passed':True,'archive_sha256':hashlib.sha256(Path(package).read_bytes()).hexdigest(),
            'launcher_sha256':hashlib.sha256(exe).hexdigest(),'requested_execution_level':'asInvoker',
            'alternate_token_process_apis_absent':True,'registry_helper_shell_api_present':True,
            'scope':'Actual package PE manifest/import contract only; does not execute UAC or a live game.'}

if __name__=='__main__':
    result=check_package(Path(sys.argv[1]))
    output=Path(sys.argv[2]);output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,indent=2)+'\n')
    print('AUTOFIX_PACKAGE_TOKEN_CONTRACT',result['archive_sha256'])
