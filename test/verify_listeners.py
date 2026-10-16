"""Check passive inventories against owned TCP/UDP sockets and empty selections."""
import argparse
import contextlib
import hashlib
import json
import os
import platform
import re
import runpy
import signal
import subprocess
import tempfile
import time
from pathlib import Path

PACK = 'NS1-Listening-Services-Map'


def sections(stdout):
    parts = re.split(r'^== (.+) ==\n', stdout, flags=re.MULTILINE)
    out = {}
    for index in range(1, len(parts), 2):
        statuses = re.findall(r'^command status: (\d+)$', parts[index+1], flags=re.MULTILINE)
        assert len(statuses) == 1
        out[parts[index]] = {'status': int(statuses[0]), 'raw': parts[index+1]}
    return out


@contextlib.contextmanager
def owned_udp(work, port, records, helpers):
    args = ['nc', '-u', '-l', '127.0.0.1', str(port)]
    output = (work/'udp.log').open('wb')
    child = subprocess.Popen(args, cwd=work, stdin=subprocess.PIPE, stdout=output, stderr=output, start_new_session=True)
    entry = {'parentTask': 'network-listeners-native', 'parentPid': os.getpid(), 'cwd': str(work), 'command': args, 'pid': child.pid, 'startTime': helpers['now'](), 'timeoutSeconds': 15}
    try:
        deadline = time.monotonic()+5
        while time.monotonic()<deadline:
            sample = helpers['command'](['ss','-lunp','sport = :'+str(port)],work,records)
            if 'pid='+str(child.pid)+',' in sample['stdout']:
                break
            assert child.poll() is None, (work/'udp.log').read_text()
            time.sleep(0.03)
        else:
            raise AssertionError('owned netcat UDP socket did not become visible')
        status = Path('/proc/'+str(child.pid)+'/status').read_text()
        uids = [int(value) for value in next(line for line in status.splitlines() if line.startswith('Uid:')).split()[1:]]
        assert uids == [os.getuid()]*4
        ready = {'pid': child.pid, 'uidFields': uids, 'host': '127.0.0.1', 'port': port, 'command': args, 'actualSocketSample': sample}
        yield ready
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid,signal.SIGTERM)
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGKILL)
            child.wait(timeout=2)
        if child.stdin:
            child.stdin.close()
        output.close()
        records.append(dict(entry,endTime=helpers['now'](),exitCode=child.returncode,childProcessGroupCleanup='owned UDP listener stopped and reaped'))
        assert child.returncode == -signal.SIGTERM and not Path('/proc/'+str(child.pid)).exists()
        assert (work/'udp.log').read_bytes() == b''


def verify(root, proof, source_only):
    hashes = {}
    for role in ('starter','solution'):
        for name in ('inventory_services.sh','README.md','network-notes.md'):
            path = root/PACK/role/name
            hashes[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
        assert (root/PACK/role/'README.md').read_bytes() == (root/PACK/'README.md').read_bytes()
    hashes[PACK+'/README.md'] = hashlib.sha256((root/PACK/'README.md').read_bytes()).hexdigest()
    if source_only:
        return {'sourceOnly': True, 'sourceHashes': hashes, 'nativeAcceptancePending': True}
    assert platform.system() == 'Linux' and os.getuid()>0
    helper_path = root/'test/verify_reachability.py'
    helpers = runpy.run_path(str(helper_path))
    class InventoryLedger(helpers['Ledger']):
        def append(self, row):
            super().append({**row, 'parentTask': 'network-listeners-native'})

    records = InventoryLedger(proof.with_suffix('.processes.jsonl'))
    observations = helpers['Ledger'](proof.with_suffix('.observations.jsonl'))
    workers, refusals, profiles = [], [], []
    namespace = os.readlink('/proc/self/ns/net')
    completion = '''probe 'TCP listener view' ss -ltnp "${socket_filter[@]}"
probe 'UDP socket view' ss -lunp "${socket_filter[@]}"
probe 'TCP descriptor ownership' lsof -nP "-iTCP${port:+:$port}" -sTCP:LISTEN
probe 'UDP descriptor ownership' lsof -nP "-iUDP${port:+:$port}"'''
    with tempfile.TemporaryDirectory(prefix='listener native quoted ') as temp:
        work = Path(temp)
        for profile in ('starter','solution','constructed-inventory-completion'):
            folder = work/profile
            folder.mkdir()
            role = 'solution' if profile == 'solution' else 'starter'
            source = (root/PACK/role/'inventory_services.sh').read_text()
            if profile == 'constructed-inventory-completion':
                before, rest = source.split('# TASK-BEGIN inventory-sections\n')
                _, after = rest.split('# TASK-END inventory-sections')
                source = before+'# TASK-BEGIN inventory-sections\n'+completion+'\n# TASK-END inventory-sections'+after
            script = folder/'inventory_services.sh'
            script.write_text(source)
            tcp_work = folder/'tcp'
            with helpers['owned_service'](tcp_work,'ipv4',False,records) as tcp:
                port = tcp['port']
                with owned_udp(folder,port,records,helpers) as udp:
                    for case,args in [('selected-live-port',[str(port)]),('broader-live-view',[])]:
                        result = helpers['command'](['bash',str(script),*args],folder,records)
                        parts = sections(result['stdout'])
                        assert result['exitCode'] == 0 and len(parts) == (2 if profile == 'starter' else 5)
                        assert all(row['status']==0 for row in parts.values())
                        assert namespace in parts['Current network namespace']['raw']
                        assert '127.0.0.1:'+str(port) in parts['TCP listener view']['raw']
                        assert '## Review the inventory' in result['stdout']
                        if profile == 'starter':
                            assert 'TODO: compare UDP' in result['stdout']
                        else:
                            assert 'pid='+str(tcp['pid'])+',' in parts['TCP listener view']['raw']
                            assert 'pid='+str(udp['pid'])+',' in parts['UDP socket view']['raw']
                            assert re.search(r'^\S+\s+'+str(tcp['pid'])+r'\s',parts['TCP descriptor ownership']['raw'],re.MULTILINE)
                            assert re.search(r'^\S+\s+'+str(udp['pid'])+r'\s',parts['UDP descriptor ownership']['raw'],re.MULTILINE)
                        observations.append({'profile':profile,'case':case,'tcp':tcp,'udp':udp,'result':result,'sections':parts})
            tcp_done = json.loads((tcp_work/'worker.json').read_text())
            assert tcp_done['socketClosed'] and not tcp_done['requests']
            workers.append({'profile':profile,'tcp':tcp_done,'udp':udp,'tcpReaped':True,'udpReaped':True,'udpLogEmpty':True})
            result = helpers['command'](['bash',str(script),str(port)],folder,records)
            parts = sections(result['stdout'])
            assert result['exitCode']==0 and '## Review the inventory' in result['stdout']
            assert parts['TCP listener view']['status']==0 and '127.0.0.1:'+str(port) not in parts['TCP listener view']['raw']
            if profile != 'starter':
                assert parts['UDP socket view']['status']==0 and '127.0.0.1:'+str(port) not in parts['UDP socket view']['raw']
                assert parts['TCP descriptor ownership']['status']==parts['UDP descriptor ownership']['status']==1
            observations.append({'profile':profile,'case':'removed-owned-listeners','port':port,'result':result,'sections':parts})
            for args in [('0',),('65536',),('old-report.md',),('80','extra')]:
                result = helpers['command'](['bash',str(script),*args],folder,records)
                assert result['exitCode']==2 and 'usage:' in result['stderr'] and 'command status:' not in result['stdout']
                refusals.append({'profile':profile,'args':list(args),'result':result})
            profiles.append({'profile':profile,'cases':3,'constructedTaskCompletion':profile=='constructed-inventory-completion','learnerNotebookCompletionInferred':False})
    assert all(hashlib.sha256((root/name).read_bytes()).hexdigest()==digest for name,digest in hashes.items())
    result = {'accepted':True,'actualLinux':True,'uid':os.getuid(),'namespace':namespace,'sourceHashes':hashes,'sourceUnchanged':True,
              'sharedHelperIdentity':{'path':'test/verify_reachability.py','sha256':hashlib.sha256(helper_path.read_bytes()).hexdigest()},
              'profiles':profiles,'observations':observations,'workers':workers,'argumentRefusals':refusals,'commandLifecycles':records,
              'ownedTCPAndUDPListenersRemoved':True,'temporaryWorkspaceRemoved':not work.exists(),
              'serviceProbesSent':False,'remoteReachabilityInferred':False,'learnerNotebookCompletionInferred':False}
    proof.parent.mkdir(parents=True,exist_ok=True)
    proof.write_text(json.dumps(result,indent=2)+'\n')
    return {'accepted':True,'profiles':3,'actualCases':9,'ownedTCPListeners':3,'ownedUDPListeners':3,'argumentRefusals':12,'outerLifecycles':len(records)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--proof',type=Path,default=Path('output/network-listeners.json'))
    parser.add_argument('--source-only',action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.root,args.proof,args.source_only)))
    except BaseException as error:
        args.proof.parent.mkdir(parents=True,exist_ok=True)
        args.proof.write_text(json.dumps({'accepted':False,'error':repr(error),'partialEvidenceRetained':True})+'\n')
        raise
