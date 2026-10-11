"""Verified helper functions; historical entrypoints excluded."""
import contextlib


import hashlib


import ipaddress


import json


import os


from pathlib import Path


import platform


import secrets


import socket


import socketserver


import struct


import subprocess


import sys


import tempfile


import threading


import time


class PilotError(Exception):
    """Messages are fixed diagnostic codes, never subprocess output."""


def require(value, code):
    if not value:
        raise PilotError(code)


def recv_exact(stream, size):
    value = b''
    while len(value) < size:
        part = stream.recv(size - len(value))
        require(part, 'UNEXPECTED_SOCKET_EOF')
        value += part
    return value


def read_name(data, offset):
    labels, seen, end = [], set(), None
    while True:
        require(offset < len(data) and offset not in seen, 'DNS_NAME_INVALID')
        seen.add(offset)
        length = data[offset]
        if length & 0xc0 == 0xc0:
            require(offset + 1 < len(data), 'DNS_POINTER_TRUNCATED')
            if end is None:
                end = offset + 2
            offset = ((length & 0x3f) << 8) | data[offset + 1]
            continue
        require(length <= 63, 'DNS_LABEL_INVALID')
        offset += 1
        if length == 0:
            return '.'.join(labels), end if end is not None else offset
        require(offset + length <= len(data), 'DNS_LABEL_TRUNCATED')
        labels.append(data[offset:offset + length].decode('ascii').lower())
        offset += length


def dns_query(name):
    ident = secrets.randbelow(65536)
    question = b''.join(bytes([len(label)]) + label.encode('ascii')
                        for label in name.split('.')) + b'\x00\x00\x01\x00\x01'
    return struct.pack('!6H', ident, 0x0100, 1, 0, 0, 0) + question


def dns_addresses(query, response):
    require(len(response) >= 12 and response[:2] == query[:2], 'DNS_ID_INVALID')
    _, flags, questions, answers, _, _ = struct.unpack('!6H', response[:12])
    require(flags & 0x8000 and not flags & 0x0200 and flags & 15 == 0,
            'DNS_RESPONSE_INVALID')
    require(questions == 1 and 0 < answers <= 32, 'DNS_ANSWER_COUNT_INVALID')
    offset = 12
    for _ in range(questions):
        _, offset = read_name(response, offset)
        offset += 4
    values = []
    for _ in range(answers):
        _, offset = read_name(response, offset)
        require(offset + 10 <= len(response), 'DNS_RECORD_TRUNCATED')
        kind, klass, _, size = struct.unpack('!HHIH', response[offset:offset + 10])
        offset += 10
        require(offset + size <= len(response), 'DNS_RDATA_TRUNCATED')
        if kind == 1 and klass == 1 and size == 4:
            values.append(socket.inet_ntoa(response[offset:offset + 4]))
        offset += size
    require(len(values) == 1, 'DNS_A_COUNT_INVALID')
    return values[0]


@contextlib.contextmanager
def local_server(server_class, handler):
    with server_class(('127.0.0.1', 0), handler) as server:
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={'poll_interval': 0.05}, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join(timeout=2)


def spare_port():
    with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
        tcp.bind(('127.0.0.1', 0))
        port = tcp.getsockname()[1]
        udp.bind(('127.0.0.1', port))
        return port


def lookup(port, name, protocol):
    query = dns_query(name)
    if protocol == 'tcp':
        with socket.create_connection(('127.0.0.1', port), timeout=3) as stream:
            stream.sendall(struct.pack('!H', len(query)) + query)
            response = recv_exact(stream, struct.unpack('!H', recv_exact(stream, 2))[0])
    else:
        with socket.socket(type=socket.SOCK_DGRAM) as stream:
            stream.settimeout(3)
            stream.connect(('127.0.0.1', port))
            stream.send(query)
            response = stream.recv(4096)
    return dns_addresses(query, response)


def socks_request(port, command, address, target_port):
    stream = socket.create_connection(('127.0.0.1', port), timeout=4)
    try:
        stream.sendall(b'\x05\x01\x00')
        require(recv_exact(stream, 2) == b'\x05\x00', 'SOCKS_AUTH_FAILED')
        stream.sendall(bytes([5, command, 0, 1]) + socket.inet_aton(address)
                       + struct.pack('!H', target_port))
        reply = recv_exact(stream, 4)
        require(reply[:3] == b'\x05\x00\x00', 'SOCKS_REQUEST_FAILED')
        require(reply[3] in (1, 4), 'SOCKS_REPLY_ADDRESS_UNSUPPORTED')
        size = 4 if reply[3] == 1 else 16
        address_bytes = recv_exact(stream, size)
        reply_port = struct.unpack('!H', recv_exact(stream, 2))[0]
        reply_ip = socket.inet_ntop(socket.AF_INET if size == 4 else socket.AF_INET6,
                                    address_bytes)
        return stream, reply_ip, reply_port
    except BaseException:
        stream.close()
        raise


def check_listeners(pid, ports):
    inodes = set()
    for fd in (Path('/proc') / str(pid) / 'fd').iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue
        if target.startswith('socket:['):
            inodes.add(target[8:-1])
    observed = set()
    for proto in ('tcp', 'tcp6', 'udp', 'udp6'):
        for row in (Path('/proc/net') / proto).read_text().splitlines()[1:]:
            fields = row.split()
            if fields[9] not in inodes:
                continue
            addr, port_hex = fields[1].split(':')
            port = int(port_hex, 16)
            if proto.startswith('tcp') and fields[3] == '0A':
                require(proto == 'tcp' and addr == '0100007F', 'PUBLIC_TCP_LISTENER')
            if port in ports:
                require(proto in ('tcp', 'udp') and addr == '0100007F',
                        'PILOT_LISTENER_NOT_LOOPBACK')
                observed.add((proto, port))
    require(observed == {(proto, port) for proto in ('tcp', 'udp') for port in ports},
            'PILOT_LISTENERS_MISSING')


