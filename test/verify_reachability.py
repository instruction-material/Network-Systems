"""Verify bounded diagnostics against real owned Linux HTTP/TCP observations."""
import argparse
import contextlib
import datetime
import hashlib
import json
import os
import platform
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PACK = 'NS2-Local-vs-Remote-Reachability-Diagnosis'


class Ledger(list):
    def __init__(self, path):
        super().__init__()
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('')

    def append(self, row):
        super().append(row)
        with self.path.open('a') as out:
            out.write(json.dumps(row)+'\n')


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def worker(directory, family, slow):
    directory = Path(directory)
    requests = []
    token = uuid.uuid4().hex

    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            requests.append({'method': 'HEAD', 'path': self.path, 'peer': list(self.client_address), 'at': now()})
            if slow:
                time.sleep(4)
                return
            self.send_response(200)
            self.send_header('X-Owned-Reachability', token)
            self.end_headers()

        def log_message(self, *_):
            pass

    class Server(HTTPServer):
        address_family = socket.AF_INET6 if family == 'ipv6' else socket.AF_INET

    host = '::1' if family == 'ipv6' else '127.0.0.1'
    server = Server((host, 0), Handler)
    server.timeout = 0.1
    ready = {'pid': os.getpid(), 'uid': os.getuid(), 'host': host, 'port': server.server_port, 'token': token, 'family': family, 'slow': slow}
    (directory / 'ready.json').write_text(json.dumps(ready))

    def stop(*_):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            server.handle_request()
    finally:
        server.server_close()
        (directory / 'worker.json').write_text(json.dumps(dict(ready, requests=requests, socketClosed=server.socket.fileno() == -1)))


def command(args, cwd, records, timeout=25):
    started = now()
    clock = time.monotonic()
    child = subprocess.Popen(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    cleanup = 'exited and reaped'
    stdout, stderr = b'', b''
    entry = {'parentTask': 'network-reachability-native', 'parentPid': os.getpid(), 'cwd': str(cwd), 'command': args, 'pid': child.pid, 'startTime': started, 'timeoutSeconds': timeout}
    try:
        stdout, stderr = child.communicate(timeout=timeout)
    except BaseException:
        cleanup = 'terminated owned process group'
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGTERM)
        try:
            stdout, stderr = child.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            stdout, stderr = child.communicate(timeout=2)
        raise
    finally:
        records.append(dict(entry, endTime=now(), exitCode=child.returncode, childProcessGroupCleanup=cleanup, elapsedSeconds=round(time.monotonic()-clock, 3), stdout=stdout.decode(), stderr=stderr.decode()))
    result = dict(records[-1], stdout=stdout.decode(), stderr=stderr.decode())
    return result


@contextlib.contextmanager
def owned_service(work, family, slow, records):
    work.mkdir()
    log = (work/'worker.log').open('wb')
    args = [sys.executable, str(Path(__file__).resolve()), '--worker', str(work), '--family', family]
    if slow:
        args.append('--slow')
    started = now()
    child = subprocess.Popen(args, cwd=work, stdout=log, stderr=log, start_new_session=True)
    entry = {'parentTask': 'network-reachability-native', 'parentPid': os.getpid(), 'cwd': str(work), 'command': args, 'pid': child.pid, 'startTime': started, 'timeoutSeconds': 45}
    try:
        deadline = time.monotonic()+5
        while not (work/'ready.json').exists() and child.poll() is None and time.monotonic()<deadline:
            time.sleep(0.02)
        assert (work/'ready.json').exists(), (work/'worker.log').read_text()
        ready = json.loads((work/'ready.json').read_text())
        assert ready['pid'] == child.pid and ready['uid'] == os.getuid()
        yield ready
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=2)
        log.close()
        records.append(dict(entry, endTime=now(), exitCode=child.returncode, childProcessGroupCleanup='owned worker stopped and reaped'))
        assert child.returncode == 0 and (work/'worker.json').exists()
        final = json.loads((work/'worker.json').read_text())
        assert final['socketClosed'] and final['pid'] == child.pid


def sections(stdout):
    found = {}
    parts = re.split(r'^== (.+) ==\n', stdout, flags=re.MULTILINE)
    for index in range(1, len(parts), 2):
        matches = re.findall(r'^command status: (\d+)$', parts[index+1], flags=re.MULTILINE)
        assert len(matches) == 1
        found[parts[index]] = int(matches[0])
    return found


def verify(root, proof, source_only):
    hashes = {}
    for role in ('starter', 'solution'):
        for name in ('diagnose_reachability.sh', 'README.md', 'network-notes.md'):
            path = root/PACK/role/name
            hashes[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
        assert (root/PACK/role/'README.md').read_bytes() == (root/PACK/'README.md').read_bytes()
    hashes[PACK+'/README.md'] = hashlib.sha256((root/PACK/'README.md').read_bytes()).hexdigest()
    if source_only:
        return {'sourceOnly': True, 'sourceHashes': hashes, 'nativeAcceptancePending': True}
    assert platform.system() == 'Linux' and os.getuid() > 0
    records = Ledger(proof.with_suffix('.processes.jsonl'))
    observations = Ledger(proof.with_suffix('.observations.jsonl'))
    workers, refusals = [], []
    configs = ['127.0.0.1', '::1', 'localhost']
    profiles = []
    with tempfile.TemporaryDirectory(prefix='reachability native quoted ') as temp:
        work = Path(temp)
        for profile in ('starter', 'solution', 'constructed-route-completion'):
            folder = work/profile
            folder.mkdir()
            role = 'solution' if profile == 'solution' else 'starter'
            text = (root/PACK/role/'diagnose_reachability.sh').read_text()
            if profile == 'constructed-route-completion':
                before, rest = text.split('# TASK-BEGIN route-evidence\n')
                _, after = rest.split('# TASK-END route-evidence')
                text = before+'# TASK-BEGIN route-evidence\n'+"probe 'Interface summary on this machine' ip -brief address\nprobe 'IPv4 routes on this machine' ip -4 route show\nprobe 'IPv6 routes on this machine' ip -6 route show\n"+'# TASK-END route-evidence'+after
            script = folder/'diagnose_reachability.sh'
            script.write_text(text)
            profile_cases = []
            last_live_port = None
            for index, host in enumerate(configs):
                family = 'ipv6' if host == '::1' else 'ipv4'
                case = ('live-ipv4', 'live-ipv6', 'changed-port-and-name')[index]
                owned = folder/case
                with owned_service(owned, family, False, records) as ready:
                    if index == 2:
                        assert ready['port'] != last_live_port
                    last_live_port = ready['port']
                    result = command(['bash', str(script), host, str(ready['port']), 'http'], folder, records)
                    states = sections(result['stdout'])
                    assert result['exitCode'] == 0 and len(states) == (4 if profile == 'starter' else 7)
                    assert all(status == 0 for status in states.values())
                    assert result['stdout'].count('X-Owned-Reachability: '+ready['token']) == 2
                    assert 'not a second-machine test' in result['stdout']
                    expected = '[::1]' if host == '::1' else host
                    assert 'Target: http://'+expected+':'+str(ready['port'])+'/' in result['stdout']
                    if family == 'ipv6':
                        assert 'http://[::1]:' in result['stdout'] and '127.0.0.1' not in result['stdout'].split('Loopback HTTP observation')[1].split('Target HTTP observation')[0]
                    observations.append({'profile': profile, 'case': case, 'ready': ready, 'result': result, 'statuses': states})
                finished = json.loads((owned/'worker.json').read_text())
                assert len(finished['requests']) == 2 and all(row['method']=='HEAD' for row in finished['requests'])
                workers.append({'profile': profile, 'case': case, 'evidence': finished, 'reaped': True})
                profile_cases.append(case)
            # The last owned listener is gone. Raw refusal remains evidence and does not abort later sections.
            result = command(['bash', str(script), '127.0.0.1', str(last_live_port), 'http'], folder, records)
            states = sections(result['stdout'])
            assert result['exitCode'] == 0
            assert states['Loopback HTTP observation on this machine'] == states['Target HTTP observation from this machine'] == 7
            assert states['Target TCP observation from this machine'] == 1
            observations.append({'profile': profile, 'case': 'removed-owned-service', 'port': last_live_port, 'result': result, 'statuses': states})
            profile_cases.append('removed-owned-service')
            for case, slow, scheme in [('http-deadline-with-live-tcp', True, 'http'), ('selected-https-on-plain-http', False, 'https')]:
                owned = folder/case
                with owned_service(owned, 'ipv4', slow, records) as ready:
                    result = command(['bash', str(script), '127.0.0.1', str(ready['port']), scheme], folder, records)
                    states = sections(result['stdout'])
                    assert result['exitCode'] == 0 and states['Target TCP observation from this machine'] == 0
                    expected = 28 if slow else 35
                    assert states['Loopback HTTP observation on this machine'] == states['Target HTTP observation from this machine'] == expected
                    assert result['elapsedSeconds'] < 12
                    if scheme == 'https':
                        assert result['stdout'].count('https://127.0.0.1:') >= 3 and ' http://' not in result['stdout']
                    observations.append({'profile': profile, 'case': case, 'ready': ready, 'result': result, 'statuses': states})
                finished = json.loads((owned/'worker.json').read_text())
                if slow:
                    assert finished['requests'] and all(row['method']=='HEAD' for row in finished['requests'])
                workers.append({'profile': profile, 'case': case, 'evidence': finished, 'reaped': True})
                profile_cases.append(case)
            for args in [('-option',), ('host/path',), ('host', '0'), ('host', '65536'), ('host', '80', 'ftp'), ('host','80','http','extra')]:
                result = command(['bash', str(script), *args], folder, records)
                assert result['exitCode'] == 2 and 'usage:' in result['stderr'] and 'command status:' not in result['stdout']
                refusals.append({'profile': profile, 'args': list(args), 'result': result})
            # This is a controlled hung command, not a claim of observed network loss.
            tools = folder/'controlled-tools'
            tools.mkdir()
            hung = tools/'nc'
            hung.write_text('#!/bin/sh\nexec sleep 30\n')
            hung.chmod(0o700)
            result = command(['env', 'PATH='+str(tools)+':'+os.environ['PATH'], 'bash', str(script), '127.0.0.1', str(last_live_port), 'http'], folder, records)
            states = sections(result['stdout'])
            assert result['exitCode'] == 0 and states['Target TCP observation from this machine'] == 124
            assert 4.5 <= result['elapsedSeconds'] < 8
            observations.append({'profile': profile, 'case': 'controlled-hung-command-deadline', 'controlledCommand': True, 'result': result, 'statuses': states})
            profile_cases.append('controlled-hung-command-deadline')
            profiles.append({'profile': profile, 'actualCases': profile_cases, 'constructedTaskCompletion': profile=='constructed-route-completion', 'learnerNotebookCompletionInferred': False})
    assert all(hashlib.sha256((root/name).read_bytes()).hexdigest() == digest for name,digest in hashes.items())
    result = {'accepted': True, 'actualLinux': True, 'uid': os.getuid(), 'sourceHashes': hashes, 'sourceUnchanged': True,
                  'profiles': profiles, 'observations': observations, 'workers': workers, 'argumentRefusals': refusals,
                  'commandLifecycles': records, 'ownedWorkersRemoved': True, 'temporaryWorkspaceRemoved': not work.exists(),
                  'secondMachineReachabilityMeasured': False, 'firewallPolicyReadOrChanged': False,
                  'realSocketFamilies': ['ipv4','ipv6'], 'learnerNotebookCompletionInferred': False}
    proof.parent.mkdir(parents=True, exist_ok=True)
    proof.write_text(json.dumps(result, indent=2)+'\n')
    return {'accepted': True, 'actualCases': len(observations), 'profiles': len(profiles), 'argumentRefusals': len(refusals), 'ownedWorkers': len(workers), 'sourceFiles': len(hashes)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--proof', type=Path, default=Path('output/network-reachability.json'))
    parser.add_argument('--source-only', action='store_true')
    parser.add_argument('--worker', type=Path)
    parser.add_argument('--family', choices=['ipv4','ipv6'], default='ipv4')
    parser.add_argument('--slow', action='store_true')
    arguments = parser.parse_args()
    if arguments.worker:
        os.umask(0o077)
        worker(arguments.worker, arguments.family, arguments.slow)
    else:
        try:
            print(json.dumps(verify(arguments.root, arguments.proof, arguments.source_only)))
        except BaseException as error:
            arguments.proof.parent.mkdir(parents=True, exist_ok=True)
            arguments.proof.write_text(json.dumps({'accepted': False, 'error': repr(error), 'partialEvidenceRetained': True})+'\n')
            raise
