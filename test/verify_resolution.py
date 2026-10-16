"""Exercise actual owned DNS records, negative answers and the separate NSS path."""
import argparse
import contextlib
import hashlib
import json
import os
import platform
import re
import runpy
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path

PACK = 'NS4-IPv4-vs-IPv6-Resolution-Comparison'
SYSTEM_FILES = ('/etc/hosts','/etc/resolv.conf','/etc/nsswitch.conf')
QUESTIONS = ('dual.course.test','v4.course.test','alias.course.test','missing.course.test','localhost')


def system_hashes():
    return {name:hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in SYSTEM_FILES}


def sections(stdout):
    parts = re.split(r'^== (.+) ==\n',stdout,flags=re.MULTILINE)
    out = {}
    for index in range(1,len(parts),2):
        status = re.findall(r'^command status: (\d+)$',parts[index+1],flags=re.MULTILINE)
        assert len(status)==1
        out[parts[index]] = {'status':int(status[0]),'raw':parts[index+1]}
    return out


def dns_response(raw):
    text = raw.split('\ncommand status:',1)[0]
    status = re.search(r'->>HEADER<<-.*status: ([A-Z]+),',text)
    rows = []
    for line in text.splitlines():
        if line.startswith(';'):
            continue
        parts = line.split()
        if len(parts)==5 and parts[1].isdigit() and parts[2]=='IN' and parts[3] in ('A','AAAA','CNAME'):
            rows.append({'name':parts[0].rstrip('.'),'ttl':int(parts[1]),'type':parts[3],'value':parts[4].rstrip('.')})
    return {'rcode':status[1] if status else None,'answers':rows}


def expected(question, kind):
    rcode = 'NXDOMAIN' if question in ('missing.course.test','localhost') else 'NOERROR'
    records = []
    if question=='alias.course.test':
        records.append({'name':question,'ttl':0,'type':'CNAME','value':'dual.course.test'})
    target = 'dual.course.test' if question=='alias.course.test' else question
    value = {'dual.course.test':{'A':'127.0.0.8','AAAA':'::1'},'v4.course.test':{'A':'127.0.0.9'}}.get(target,{}).get(kind)
    if value is not None:
        records.append({'name':target,'ttl':0,'type':kind,'value':value})
    return {'rcode':rcode,'answers':records}


@contextlib.contextmanager
def owned_dns(work, records, helpers):
    work.mkdir()
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as reservation:
        reservation.bind(('127.0.0.1',0))
        port = reservation.getsockname()[1]
    args = ['dnsmasq','--no-daemon','--conf-file=/dev/null','--listen-address=127.0.0.1','--bind-interfaces',
            '--port='+str(port),'--no-hosts','--no-resolv','--log-facility=-','--log-queries=extra',
            '--local=/course.test/','--local=/localhost/','--host-record=dual.course.test,127.0.0.8,::1',
            '--host-record=v4.course.test,127.0.0.9','--cname=alias.course.test,dual.course.test']
    output = (work/'dnsmasq.log').open('wb')
    child = subprocess.Popen(args,cwd=work,stdin=subprocess.DEVNULL,stdout=output,stderr=output,start_new_session=True)
    entry = {'parentTask':'network-resolution-native','parentPid':os.getpid(),'cwd':str(work),'command':args,'pid':child.pid,'startTime':helpers['now'](),'timeoutSeconds':120}
    try:
        deadline = time.monotonic()+5
        while time.monotonic()<deadline:
            sample = helpers['command'](['ss','-lntup','sport = :'+str(port)],work,records)
            if sample['stdout'].count('pid='+str(child.pid)+',')>=2:
                break
            assert child.poll() is None,(work/'dnsmasq.log').read_text()
            time.sleep(0.03)
        else:
            raise AssertionError('owned DNS TCP/UDP listeners did not become visible')
        first = helpers['command'](['dig','+time=1','+tries=1','@127.0.0.1','-p',str(port),'dual.course.test','A'],work,records)
        assert first['exitCode']==0 and dns_response(first['stdout'])==expected('dual.course.test','A')
        uids = [int(value) for value in next(line for line in Path('/proc/'+str(child.pid)+'/status').read_text().splitlines() if line.startswith('Uid:')).split()[1:]]
        assert uids==[os.getuid()]*4
        ready = {'pid':child.pid,'uidFields':uids,'host':'127.0.0.1','port':port,'command':args,'actualSocketSample':sample,'actualReadyQuery':first}
        yield ready
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid,signal.SIGTERM)
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGKILL)
            child.wait(timeout=2)
        output.close()
        records.append(dict(entry,endTime=helpers['now'](),exitCode=child.returncode,childProcessGroupCleanup='owned resolver stopped and reaped'))
        assert child.returncode in (0,-signal.SIGTERM) and not Path('/proc/'+str(child.pid)).exists()


def verify(root, proof, source_only):
    hashes = {}
    for role in ('starter','solution'):
        for name in ('compare_resolution.sh','README.md','network-notes.md'):
            path = root/PACK/role/name
            hashes[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
        assert (root/PACK/role/'README.md').read_bytes()==(root/PACK/'README.md').read_bytes()
    hashes[PACK+'/README.md'] = hashlib.sha256((root/PACK/'README.md').read_bytes()).hexdigest()
    if source_only:
        return {'sourceOnly':True,'sourceHashes':hashes,'nativeAcceptancePending':True}
    assert platform.system()=='Linux' and os.getuid()>0
    before = system_hashes()
    helper_path = root/'test/verify_reachability.py'
    helpers = runpy.run_path(str(helper_path))

    class ResolutionLedger(helpers['Ledger']):
        def append(self,row):
            super().append({**row,'parentTask':'network-resolution-native'})

    records = ResolutionLedger(proof.with_suffix('.processes.jsonl'))
    observations = helpers['Ledger'](proof.with_suffix('.observations.jsonl'))
    workers,refusals,profiles = [],[],[]
    nss = "probe 'System NSS address view' getent ahosts \"$query_name\""
    with tempfile.TemporaryDirectory(prefix='resolution native quoted ') as temp:
        work = Path(temp)
        for profile in ('starter','solution','constructed-system-lookup-completion'):
            folder = work/profile
            folder.mkdir()
            role = 'solution' if profile=='solution' else 'starter'
            source = (root/PACK/role/'compare_resolution.sh').read_text()
            if profile=='constructed-system-lookup-completion':
                first,rest = source.split('# TASK-BEGIN system-lookup\n')
                _,last = rest.split('# TASK-END system-lookup')
                source = first+'# TASK-BEGIN system-lookup\n'+nss+'\n# TASK-END system-lookup'+last
            script = folder/'compare_resolution.sh'
            script.write_text(source)
            server_work = folder/'owned DNS'
            with owned_dns(server_work,records,helpers) as ready:
                for question in QUESTIONS:
                    result = helpers['command'](['bash',str(script),question,'127.0.0.1',str(ready['port'])],folder,records)
                    parts = sections(result['stdout'])
                    assert result['exitCode']==0 and len(parts)==(2 if profile=='starter' else 3)
                    assert parts['DNS A response']['status']==parts['DNS AAAA response']['status']==0
                    responses = {kind:dns_response(parts['DNS '+kind+' response']['raw']) for kind in ('A','AAAA')}
                    assert responses=={kind:expected(question,kind) for kind in ('A','AAAA')}
                    assert all('127.0.0.1#'+str(ready['port']) in parts['DNS '+kind+' response']['raw'] for kind in ('A','AAAA'))
                    assert 'The selected server applies only to dig.' in result['stdout']
                    if profile=='starter':
                        assert 'TODO: compare the separate system NSS lookup' in result['stdout']
                    else:
                        assert parts['System NSS address view']['status'] in (0,2,124)
                        if question=='localhost':
                            assert parts['System NSS address view']['status']==0
                            assert any(line.split() and line.split()[0] in ('127.0.0.1','::1') for line in parts['System NSS address view']['raw'].splitlines())
                    observations.append({'profile':profile,'case':question,'ready':ready,'result':result,'sections':parts,'dnsResponses':responses})
            log = (server_work/'dnsmasq.log').read_text()
            for question in QUESTIONS:
                for kind in ('A','AAAA'):
                    assert 'query['+kind+'] '+question+' ' in log
            workers.append({'profile':profile,'ready':ready,'actualLog':log,'stoppedAndReaped':True})
            result = helpers['command'](['bash',str(script),'localhost','127.0.0.1',str(ready['port'])],folder,records)
            parts = sections(result['stdout'])
            assert result['exitCode']==0 and parts['DNS A response']['status']==parts['DNS AAAA response']['status']==9
            assert all(dns_response(parts['DNS '+kind+' response']['raw'])['rcode'] is None for kind in ('A','AAAA'))
            assert '## Interpret the two lookup paths' in result['stdout']
            if profile!='starter':
                assert parts['System NSS address view']['status']==0
            observations.append({'profile':profile,'case':'removed-owned-resolver','port':ready['port'],'result':result,'sections':parts})
            for invalid in [('-option',),('name/path',),('name','-server'),('name','127.0.0.1','0'),('name','127.0.0.1','65536'),('name','127.0.0.1','53','extra')]:
                result = helpers['command'](['bash',str(script),*invalid],folder,records)
                assert result['exitCode']==2 and 'usage:' in result['stderr'] and 'command status:' not in result['stdout']
                refusals.append({'profile':profile,'args':list(invalid),'result':result})
            profiles.append({'profile':profile,'cases':6,'constructedTaskCompletion':profile=='constructed-system-lookup-completion','learnerNotebookCompletionInferred':False})
    after = system_hashes()
    assert before==after
    assert all(hashlib.sha256((root/name).read_bytes()).hexdigest()==digest for name,digest in hashes.items())
    result = {'accepted':True,'actualLinux':True,'uid':os.getuid(),'sourceHashes':hashes,'sourceUnchanged':True,
              'sharedHelperIdentity':{'path':'test/verify_reachability.py','sha256':hashlib.sha256(helper_path.read_bytes()).hexdigest()},
              'profiles':profiles,'observations':observations,'workers':workers,'argumentRefusals':refusals,'commandLifecycles':records,
              'systemFileHashesBefore':before,'systemFileHashesAfter':after,'systemNameServiceConfigurationUnchanged':True,
              'ownedResolversRemoved':True,'temporaryWorkspaceRemoved':not work.exists(),
              'DNSQueryTransport':'IPv4 loopback to an owned high-port resolver','applicationConnectionOrIPv6PathProbed':False,'learnerNotebookCompletionInferred':False}
    proof.parent.mkdir(parents=True,exist_ok=True)
    proof.write_text(json.dumps(result,indent=2)+'\n')
    return {'accepted':True,'profiles':3,'actualCases':18,'actualTypedDNSResponses':30,'ownedResolvers':3,'argumentRefusals':18,'outerLifecycles':len(records)}


if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--proof',type=Path,default=Path('output/network-resolution.json'))
    parser.add_argument('--source-only',action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.root,args.proof,args.source_only)))
    except BaseException as error:
        args.proof.parent.mkdir(parents=True,exist_ok=True)
        args.proof.write_text(json.dumps({'accepted':False,'error':repr(error),'partialEvidenceRetained':True})+'\n')
        raise
