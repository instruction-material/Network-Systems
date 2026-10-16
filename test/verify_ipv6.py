"""Verify real IPv6 family endpoints, exact source roles and independent arithmetic."""
import argparse
import ast
import contextlib
import datetime
import hashlib
import importlib.util
import ipaddress
import json
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

from verify_naming import complete

sys.dont_write_bytecode = True
PARTIAL = None

PACKS = {
    'NS-08-unit-8-ipv6-in-practice': 'core',
    'NS-17-unit-8-ipv6-in-practice-supplemental-2': 'transfer',
    'NS-18-unit-8-ipv6-in-practice-supplemental-3': 'extension',
}
FILES = ('main.py', 'ipv6_lab.py', 'network-notes.md', 'ipv6-practice-case.md', 'README.md')


def hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for pack in PACKS for path in [root / pack / 'README.md',
                *[root / pack / role / name for role in ('starter', 'solution') for name in FILES]]}


def run(args, cwd, records):
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    child = subprocess.Popen(args, cwd=cwd, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    cleanup = 'exited and reaped'
    try:
        out, err = child.communicate(timeout=45)
    except BaseException:
        cleanup = 'owned process group stopped and reaped'
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGTERM)
        try:
            child.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.communicate(timeout=3)
        raise
    finally:
        records.append({'parentTask': 'network-ipv6-native', 'parentPid': os.getpid(),
                        'cwd': str(cwd), 'command': args, 'pid': child.pid,
                        'startTime': started, 'endTime': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        'exitCode': child.returncode, 'timeoutSeconds': 45,
                        'childProcessGroupCleanup': cleanup})
    records[-1].update(stdout=out.decode(), stderr=err.decode())
    return child.returncode, out.decode(), err.decode()


def independent_prefix(evidence):
    raw, bits = evidence['prefixInput'].split('/')
    bits = int(bits)
    entered = int(ipaddress.IPv6Address(raw))
    count = 1 << (128 - bits)
    first = (entered // count) * count
    return {'enteredPrefix': evidence['prefixInput'],
            'network': str(ipaddress.IPv6Address(first)) + '/' + str(bits),
            'prefixLength': bits, 'addressCount': count, 'hostBitsMasked': entered != first,
            'rows': [{'address': str(ipaddress.IPv6Address(text.strip())),
                      'inPrefix': first <= int(ipaddress.IPv6Address(text.strip())) < first + count}
                     for text in evidence['candidateInput'].split(',')],
            'scope': 'calculation only; no address, route or neighbor state configured'}


def check(evidence, kind):
    assert evidence['kind'] == 'ipv6-loopback'
    env, ready, worker = evidence['environment'], evidence['ready'], evidence['workerResult']
    assert env['platform'] == 'linux' and env['uid'] > 0 and env['networkNamespace'].startswith('net:[')
    assert any(row['ifname'] == 'lo' and any(info.get('local') == '::1' for info in row['addr_info']) for row in evidence['addresses'])
    assert evidence['route'][0]['dev'] == 'lo' and isinstance(evidence['neighbors'], list)
    assert not evidence['internetIPv6Measured'] and not evidence['neighborDiscoveryMeasured'] and not evidence['dnsFamilySelectionMeasured']
    assert json.loads(evidence['readyLine']) == ready
    assert ready['pid'] == worker['pid'] == evidence['workerProcess']['pid']
    assert ready['uid'] == worker['uid'] == env['uid']
    assert evidence['workerProcUidFields'] == [str(env['uid'])] * 4
    assert ready['token'] == worker['token'] and len(ready['token']) == 32 and ready['ipv6Only'] == 1
    assert ready['binding'] == evidence['binding']
    paired = evidence['binding'] == 'paired'
    listeners = ready['listeners']
    assert len(listeners) == 1 + int(paired)
    v6 = next(row for row in listeners if row['family'] == 10)
    port = v6['port']
    assert v6['address'] == '::1' and 1024 <= port <= 65535
    assert ready['ipv4Control'] == {'family': 2, 'address': '127.0.0.1', 'port': port, 'listening': paired}
    if paired:
        assert next(row for row in listeners if row['family'] == 2) == {'family': 2, 'address': '127.0.0.1', 'port': port}
    pid = 'pid=' + str(ready['pid']) + ','
    for family, literal in [('6', '::1'), ('4', '127.0.0.1')]:
        matches = [line for line in evidence['listeners' + family + 'During'].splitlines()
                   if pid in line and any(literal in value and value.endswith(':' + str(port)) for value in line.split())]
        assert bool(matches) == (family == '6' or paired)
        assert not any(pid in line for line in evidence['listeners' + family + 'After'].splitlines())
    commands = {row['pid']: row for row in evidence['commands']}
    assert len(commands) == len(evidence['commands']) == 9
    assert [row['command'][1:] for row in evidence['commands'][:3]] == [
        ['-j', '-6', 'address', 'show'], ['-j', '-6', 'route', 'get', '::1'], ['-j', '-6', 'neigh', 'show']]
    assert len(evidence['probes']) == 2 and [row['family'] for row in evidence['probes']] == [4, 6]
    expected_requests = []
    for probe in evidence['probes']:
        command = commands[probe['commandPid']]
        family = probe['family']
        literal = '127.0.0.1' if family == 4 else '[::1]'
        assert command['command'][1:] == ['--noproxy', '*', '--ipv' + str(family), '--silent', '--show-error', '--include', '--max-time', '3', 'http://' + literal + ':' + str(port) + '/ipv6-lab']
        assert probe['exitCode'] == command['exitCode'] == (7 if family == 4 and not paired else 0)
        if probe['exitCode']:
            assert probe['response'] is None and 'HTTP/1.1 200 OK' not in command['stdout'] and command['stderr']
        else:
            header, body = command['stdout'].split('\r\n\r\n', 1)
            assert header.startswith('HTTP/1.1 200 OK')
            value = {'token': ready['token'], 'message': evidence['message'],
                     'family': 2 if family == 4 else 10,
                     'address': '127.0.0.1' if family == 4 else '::1',
                     'port': port, 'path': '/ipv6-lab'}
            assert json.loads(body) == probe['response'] == value
            expected_requests.append(value)
    assert [row['response'] for row in worker['requests']] == expected_requests
    for request in worker['requests']:
        local, peer = request['local'], request['peer']
        assert peer['address'] == local['address'] and peer['port'] > 0
        assert request['requestHeader'].startswith('GET /ipv6-lab HTTP/1.1\r\n')
        assert ('Host: ' + ('[::1]' if local['family'] == 10 else '127.0.0.1') + ':' + str(port) + '\r\n') in request['requestHeader']
        assert evidence['workerProcess']['startTime'] <= request['at'] <= evidence['workerProcess']['endTime']
    assert worker['socketsClosed'] and evidence['workerProcess']['exitCode'] == 0 and evidence['workerProcess']['reaped']
    assert json.loads(evidence['workerProcess']['stdout']) == worker
    for row in [*evidence['commands'], evidence['workerProcess']]:
        assert row['parentTask'] == 'network-ipv6-lab' and row['parentPid'] == env['pid'] and row['cwd'] == env['cwd']
        assert row['pid'] > 0 and row['startTime'] <= row['endTime'] and row['elapsedSeconds'] < row['timeoutSeconds'] + 1
        assert row['childProcessGroupCleanup'] == 'exited and reaped'
    table = independent_prefix(evidence)
    assert evidence['prefixTable'] == table
    if kind == 'core':
        return {'ipv6Endpoint': v6, 'observedResponseFamilies': [row['family'] for row in evidence['probes'] if row['exitCode'] == 0], 'namespace': env['networkNamespace']}
    if kind == 'transfer':
        first = int(ipaddress.IPv6Address(table['network'].split('/')[0]))
        return {'network': table['network'], 'addressCount': table['addressCount'],
                'offsets': [int(ipaddress.IPv6Address(row['address'])) - first if row['inPrefix'] else None for row in table['rows']]}
    return {'binding': evidence['binding'], 'sameNumericPort': len({row['port'] for row in listeners}) == 1,
            'ipv6Only': ready['ipv6Only'], 'ipv4HTTP': paired, 'ipv6HTTP': True,
            'singleWildcardSocketTested': False}


def verify(root, source_only, proof):
    global PARTIAL
    before = hashes(root)
    for pack in PACKS:
        for role in ('starter', 'solution'):
            for name in FILES:
                raw = (root / pack / role / name).read_bytes()
                if name.endswith('.py'):
                    ast.parse(raw, feature_version=(3, 10))
                if name in ('README.md', 'ipv6-practice-case.md'):
                    expected = (root / pack / 'README.md').read_bytes() if name == 'README.md' else (root / next(iter(PACKS)) / 'starter' / name).read_bytes()
                    assert raw == expected
    module_path = root / next(iter(PACKS)) / 'starter/ipv6_lab.py'
    spec = importlib.util.spec_from_file_location('ipv6_source', module_path)
    source = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(source)
    for prefix, candidates, expected in [
        ('::1/128', '::,::1,::2', [False, True, False]),
        ('2001:db8::/126', '2001:db8::,2001:db8::3,2001:db8::4', [True, True, False]),
        ('2001:db8::1/127', '2001:db8::,2001:db8::1,2001:db8::2', [True, True, False]),
        ('2001:db8::1/128', '2001:db8::,2001:db8::1,2001:db8::2', [False, True, False]),
        ('::/0', '::,::1,ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', [True, True, True]),
    ]:
        assert [row['inPrefix'] for row in source.prefix_table(prefix, candidates)['rows']] == expected
    result = {'accepted': False, 'sourceOnly': source_only, 'sourceHashes': before,
              'knownPrefixTables': 5, 'observations': [], 'argumentRefusals': [], 'commandLifecycles': [],
              'sharedCompletionHelper': {'path': 'test/verify_naming.py', 'sha256': hashlib.sha256((root / 'test/verify_naming.py').read_bytes()).hexdigest()},
              'learnerNotebookCompletionInferred': False, 'activeNDOrRouterAdvertisementsOrFirewallMeasured': False}
    PARTIAL = result
    if source_only:
        return result
    assert sys.platform == 'linux' and os.geteuid() > 0
    with tempfile.TemporaryDirectory(prefix='ipv6 native quoted ') as temp:
        for pack, kind in PACKS.items():
            for role in ('untouched-starter', 'constructed-completion', 'reference'):
                source_role = 'solution' if role == 'reference' else 'starter'
                work = Path(temp) / pack / role
                work.mkdir(parents=True)
                for name in FILES:
                    (work / name).write_bytes((root / pack / source_role / name).read_bytes())
                if role == 'constructed-completion':
                    (work / 'main.py').write_text(complete((work / 'main.py').read_text(), (root / pack / 'solution/main.py').read_text()))
                for case, args in [
                    ('default', []), ('v6-only', ['--binding', 'v6-only']),
                    ('paired', ['--binding', 'paired', '--message', 'Paired café']),
                    ('single-prefix', ['--binding', 'paired', '--prefix', '2001:db8::1/128', '--candidates', '2001:db8::,2001:db8::1,2001:db8::2']),
                ]:
                    status, stdout, stderr = run([sys.executable, 'main.py', *args], work, result['commandLifecycles'])
                    assert status == 0 and stderr == '', (pack, role, case, stdout, stderr)
                    evidence = json.loads(stdout)
                    expected = check(evidence, kind)
                    assert evidence['analysis'] == (None if role == 'untouched-starter' else expected)
                    result['observations'].append({'pack': pack, 'role': role, 'case': case, 'evidence': evidence})
                for args in [ ['--prefix', '192.0.2.0/24'], ['--prefix', '::/129'], ['--candidates', '::1,'], ['--message', 'x'], ['--prefix', 'fe80::1%lo/64'] ]:
                    status, stdout, stderr = run([sys.executable, 'main.py', *args], work, result['commandLifecycles'])
                    assert status == 2 and stderr
                    assert 'ready' not in json.loads(stdout).get('evidence', {})
                    result['argumentRefusals'].append({'pack': pack, 'role': role, 'arguments': args})
    assert hashes(root) == before
    result.update(accepted=True, actualLinux=True, uid=os.geteuid(), sourceUnchanged=True,
                  temporaryWorkspaceRemoved=True, actualCases=len(result['observations']))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-only', action='store_true')
    parser.add_argument('--proof', type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = verify(Path(__file__).resolve().parents[1], arguments.source_only, arguments.proof)
    except BaseException as error:
        failure = PARTIAL or {'accepted': False}
        failure['error'] = str(error)
        arguments.proof.parent.mkdir(parents=True, exist_ok=True)
        arguments.proof.write_text(json.dumps(failure, indent=2) + '\n')
        raise
    arguments.proof.parent.mkdir(parents=True, exist_ok=True)
    arguments.proof.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ('accepted', 'sourceOnly', 'knownPrefixTables')}))
