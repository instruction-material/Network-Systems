"""Owned IPv6 loopback observations; prefix arithmetic never changes the host."""
import contextlib
import datetime
import errno
import ipaddress
import json
import os
import platform
import secrets
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def inputs(message, binding, prefix, candidates):
    if not 2 <= len(message.encode('utf-8')) <= 128 or '\n' in message or '\r' in message:
        raise ValueError('Use a message of 2 to 128 UTF-8 bytes without newlines.')
    if binding not in ('v6-only', 'paired'):
        raise ValueError('Choose v6-only or paired loopback listeners.')
    if len(prefix) > 128 or len(candidates) > 4096:
        raise ValueError('Use a short IPv6 prefix and at most 32 address literals.')
    if '%' in prefix or '%' in candidates:
        raise ValueError('Keep zone identifiers separate from this prefix calculation.')
    interface = ipaddress.IPv6Interface(prefix)
    values = candidates.split(',')
    if not 1 <= len(values) <= 32 or any(not value.strip() for value in values):
        raise ValueError('Use 1 to 32 comma-separated IPv6 literals.')
    addresses = [ipaddress.IPv6Address(value.strip()) for value in values]
    return interface, addresses


def prefix_table(prefix, candidates):
    interface, addresses = inputs('Address table', 'v6-only', prefix, candidates)
    network = interface.network
    return {
        'enteredPrefix': prefix, 'network': str(network),
        'prefixLength': network.prefixlen, 'addressCount': network.num_addresses,
        'hostBitsMasked': interface.ip != network.network_address,
        'rows': [{'address': str(address), 'inPrefix': address in network}
                 for address in addresses],
        'scope': 'calculation only; no address, route or neighbor state configured',
    }


def stop_group(process):
    if process.poll() is None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)


def command(args, records, deadline=None):
    timeout = min(5, deadline - time.monotonic()) if deadline else 5
    if timeout <= 0:
        raise TimeoutError('The owned observation deadline expired.')
    started, tick = now(), time.monotonic()
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    stdout = stderr = b''
    cleanup = 'exited and reaped'
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        cleanup = 'owned process group stopped and reaped'
        stop_group(process)
        stdout, stderr = process.communicate(timeout=2)
        raise
    finally:
        records.append({
            'parentTask': 'network-ipv6-lab', 'parentPid': os.getpid(),
            'cwd': str(Path.cwd()), 'command': args, 'pid': process.pid,
            'startTime': started, 'endTime': now(), 'exitCode': process.returncode,
            'timeoutSeconds': timeout, 'elapsedSeconds': time.monotonic() - tick,
            'childProcessGroupCleanup': cleanup,
            'stdout': stdout.decode('utf-8', errors='replace'),
            'stderr': stderr.decode('utf-8', errors='replace'),
        })
    return records[-1]


def json_command(args, records):
    row = command(args, records)
    if row['exitCode']:
        raise ValueError('Linux observation failed: ' + row['stderr'])
    return json.loads(row['stdout'])


def endpoint(sock):
    address = sock.getsockname()
    return {'family': int(sock.family), 'address': address[0], 'port': address[1]}


def owned_worker(config):
    requests = []
    with contextlib.ExitStack() as stack:
        # Bind both families exclusively before announcing readiness. The IPv4
        # control is deliberately not listening in v6-only mode, so a comparison
        # cannot accidentally send an application request to an unrelated owner.
        for _ in range(32):
            v6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            v4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                v6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                v6.bind(('::1', 0))
                v4.bind(('127.0.0.1', v6.getsockname()[1]))
                break
            except OSError as error:
                v6.close()
                v4.close()
                if error.errno != errno.EADDRINUSE:
                    raise
        else:
            raise OSError('No exclusive paired loopback port was available.')
        stack.callback(v6.close)
        stack.callback(v4.close)
        v6.listen(2)
        listeners = [v6]
        if config['binding'] == 'paired':
            v4.listen(2)
            listeners.append(v4)
        ready = {'pid': os.getpid(), 'uid': os.geteuid(), 'token': config['token'],
                 'binding': config['binding'], 'ipv6Only': v6.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY),
                 'listeners': [endpoint(sock) for sock in listeners],
                 'ipv4Control': {**endpoint(v4), 'listening': v4 in listeners}}
        print(json.dumps(ready), flush=True)
        deadline = time.monotonic() + 20
        with selectors.DefaultSelector() as selected:
            for sock in listeners:
                selected.register(sock, selectors.EVENT_READ)
            while len(requests) < len(listeners):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('Owned loopback request deadline expired.')
                available = selected.select(remaining)
                if not available:
                    raise TimeoutError('No bounded owned HTTP request arrived.')
                for key, _mask in available:
                    server = key.fileobj
                    connection, peer = server.accept()
                    with connection:
                        connection.settimeout(min(2, max(0.1, deadline - time.monotonic())))
                        header = b''
                        while b'\r\n\r\n' not in header:
                            part = connection.recv(512)
                            if not part or len(header) + len(part) > 4096:
                                raise ValueError('Incomplete or oversized owned HTTP request.')
                            header += part
                        text = header.decode('ascii')
                        if text.split('\r\n', 1)[0] != 'GET /ipv6-lab HTTP/1.1':
                            raise ValueError('Unexpected owned HTTP request line.')
                        local = endpoint(connection)
                        body = {'token': config['token'], 'message': config['message'],
                                'family': local['family'], 'address': local['address'],
                                'port': local['port'], 'path': '/ipv6-lab'}
                        encoded = json.dumps(body, ensure_ascii=True).encode()
                        response = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(encoded)).encode() + b'\r\nConnection: close\r\n\r\n' + encoded
                        connection.sendall(response)
                        requests.append({'at': now(), 'local': local,
                                         'peer': {'address': peer[0], 'port': peer[1]},
                                         'requestHeader': text, 'response': body})
    return {'pid': os.getpid(), 'uid': os.geteuid(), 'token': config['token'],
            'requests': requests, 'socketsClosed': True}


def with_worker(config, operate, evidence):
    args = [sys.executable, str(Path(__file__).resolve()), '--worker', json.dumps(config)]
    started, tick = now(), time.monotonic()
    deadline = tick + 30
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True, bufsize=0)
    cleanup = 'exited and reaped'
    stdout = stderr = b''
    try:
        with selectors.DefaultSelector() as selected:
            selected.register(child.stdout, selectors.EVENT_READ)
            if not selected.select(8):
                raise TimeoutError('Owned IPv6 worker did not announce readiness.')
        raw = child.stdout.readline(4096)
        if not raw.endswith(b'\n'):
            raise ValueError('Owned IPv6 readiness announcement was incomplete.')
        evidence['readyLine'] = raw.decode()
        ready = json.loads(raw)
        if ready['pid'] != child.pid or ready['uid'] != os.geteuid() or ready['token'] != config['token']:
            raise ValueError('Owned worker identity did not match its readiness record.')
        evidence['ready'] = ready
        evidence['workerProcUidFields'] = next(line.split()[1:] for line in Path(f'/proc/{child.pid}/status').read_text().splitlines() if line.startswith('Uid:'))
        operate(ready, deadline)
        stdout, stderr = child.communicate(timeout=max(0.1, deadline - time.monotonic()))
        if child.returncode or stderr:
            raise ValueError('Owned IPv6 worker failed: ' + stderr.decode(errors='replace'))
        evidence['workerResult'] = json.loads(stdout)
    finally:
        if child.poll() is None:
            cleanup = 'owned process group stopped and reaped'
            stop_group(child)
        if not stdout:
            stdout, stderr = child.communicate(timeout=2)
        for pipe in (child.stdout, child.stderr):
            pipe.close()
        evidence['workerProcess'] = {
            'parentTask': 'network-ipv6-lab', 'parentPid': os.getpid(),
            'cwd': str(Path.cwd()), 'command': args, 'pid': child.pid,
            'startTime': started, 'endTime': now(), 'exitCode': child.returncode,
            'timeoutSeconds': 30, 'elapsedSeconds': time.monotonic() - tick,
            'childProcessGroupCleanup': cleanup, 'reaped': child.poll() is not None,
            'stdout': stdout.decode(errors='replace'), 'stderr': stderr.decode(errors='replace'),
        }


def observe(message, binding, prefix, candidates, evidence):
    inputs(message, binding, prefix, candidates)
    if sys.platform != 'linux' or os.geteuid() == 0:
        raise ValueError('Use an ordinary account in the selected owned Linux lab.')
    tools = {name: shutil.which(name) for name in ('ip', 'ss', 'curl')}
    if not all(tools.values()):
        raise ValueError('Install iproute2 and curl in the Linux lab first.')
    evidence.update(kind='ipv6-loopback', message=message, binding=binding,
                    prefixInput=prefix, candidateInput=candidates, commands=[],
                    environment={'platform': sys.platform, 'kernel': platform.release(),
                                 'hostname': socket.gethostname(), 'pid': os.getpid(),
                                 'uid': os.geteuid(), 'cwd': str(Path.cwd()),
                                 'networkNamespace': os.readlink('/proc/self/ns/net'), 'tools': tools},
                    internetIPv6Measured=False, neighborDiscoveryMeasured=False,
                    dnsFamilySelectionMeasured=False)
    records = evidence['commands']
    evidence['addresses'] = json_command([tools['ip'], '-j', '-6', 'address', 'show'], records)
    evidence['route'] = json_command([tools['ip'], '-j', '-6', 'route', 'get', '::1'], records)
    evidence['neighbors'] = json_command([tools['ip'], '-j', '-6', 'neigh', 'show'], records)
    evidence['prefixTable'] = prefix_table(prefix, candidates)
    config = {'binding': binding, 'message': message, 'token': secrets.token_hex(16)}

    def operate(ready, deadline):
        for family in ('4', '6'):
            row = command([tools['ss'], '-H', '-' + family, '-ltnp'], records, deadline)
            if row['exitCode']:
                raise ValueError('Socket inventory failed: ' + row['stderr'])
            evidence['listeners' + family + 'During'] = row['stdout']
        port = ready['listeners'][0]['port']
        probes = []
        # Probe the IPv4 control while its non-listening bind is still held.
        for family, address in (('4', '127.0.0.1'), ('6', '[::1]')):
            row = command([tools['curl'], '--noproxy', '*', '--ipv' + family,
                           '--silent', '--show-error', '--include', '--max-time', '3',
                           'http://' + address + ':' + str(port) + '/ipv6-lab'], records, deadline)
            response = None
            if row['exitCode'] == 0:
                header, body = row['stdout'].split('\r\n\r\n', 1)
                if not header.startswith('HTTP/1.1 200 OK'):
                    raise ValueError('Owned endpoint did not return HTTP 200.')
                response = json.loads(body)
                if response['token'] != config['token'] or response['family'] != int(socket.AF_INET if family == '4' else socket.AF_INET6):
                    raise ValueError('Response did not identify the owned family endpoint.')
            elif not (family == '4' and binding == 'v6-only' and row['exitCode'] == 7):
                raise ValueError('Unexpected loopback probe result: ' + row['stderr'])
            probes.append({'family': int(family), 'commandPid': row['pid'],
                           'exitCode': row['exitCode'], 'response': response})
        evidence['probes'] = probes

    with_worker(config, operate, evidence)
    for family in ('4', '6'):
        row = command([tools['ss'], '-H', '-' + family, '-ltnp'], records)
        if row['exitCode']:
            raise ValueError('Final socket inventory failed: ' + row['stderr'])
        evidence['listeners' + family + 'After'] = row['stdout']
    return evidence


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] != '--worker':
        raise SystemExit('Run main.py; this file supplies its owned loopback worker.')
    print(json.dumps(owned_worker(json.loads(sys.argv[2]))), flush=True)
