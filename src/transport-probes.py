"""Verified helper functions; historical entrypoints excluded."""
import argparse


import copy


import fcntl


import hashlib


import http.client


import importlib.util


import ipaddress


import json


import os


from pathlib import Path


import secrets


import shutil


import signal


import socket


import ssl


import stat


import struct


import subprocess


import sys


import tempfile


import time


DNS_PORT = 19053


SOCKS_PORT = 19080


FAKE_RANGE = '198.18.0.0/16'


FAKE_POOL = ipaddress.ip_network(FAKE_RANGE)


class TrialError(Exception):
    """Only fixed diagnostic codes may be used as messages."""


def require(condition, code):
    if not condition:
        raise TrialError(code)


def backend_config():
    # Trial domains are deliberately small and explicit; no claim of full coverage.
    # The backend must reject private/reserved REAL destinations after restoration.
    blocked = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
               '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
               '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
               '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4']
    lines = [f'  - IP-CIDR,{prefix},REJECT' for prefix in blocked]
    lines += [f'  - IP-CIDR6,{prefix},REJECT' for prefix in
              ('::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8')]
    return f'''mode: rule
log-level: warning
ipv6: false
allow-lan: false
bind-address: 127.0.0.1
socks-port: {SOCKS_PORT}
find-process-mode: 'off'
profile:
  store-selected: false
  store-fake-ip: true
sniffer:
  enable: false
tun:
  enable: false
dns:
  enable: true
  listen: 127.0.0.1:{DNS_PORT}
  ipv6: false
  use-hosts: false
  use-system-hosts: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter-mode: rule
  fake-ip-filter:
    - DOMAIN,checkip.amazonaws.com,real-ip
    - DOMAIN,api.ipify.org,fake-ip
    - DOMAIN,stun.l.google.com,fake-ip
    - MATCH,real-ip
  default-nameserver:
    - 1.1.1.1
  nameserver:
    - https://1.1.1.1/dns-query
rules:
''' + '\n'.join(lines) + '\n  - MATCH,DIRECT\n'


def https_ip(module, socks_port, destination):
    stream, _, _ = module.socks_request(socks_port, 1, destination, 443)
    try:
        stream.settimeout(10)
        with ssl.create_default_context().wrap_socket(stream, server_hostname='api.ipify.org') as tls:
            tls.sendall(b'GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n')
            response = http.client.HTTPResponse(tls)
            response.begin()
            require(response.status == 200, 'HTTPS_IP_CHECK_STATUS_FAILED')
            value = response.read(1025).decode('ascii').strip()
            require(value == PUBLIC_IP, 'HTTPS_IP_CHECK_ADDRESS_MISMATCH')
    finally:
        stream.close()


def dns_vless(module, port, name, protocol):
    query = module.dns_query(name)
    if protocol == 'tcp':
        stream, _, _ = module.socks_request(port, 1, '127.0.0.1', DNS_PORT)
        with stream:
            stream.sendall(struct.pack('!H', len(query)) + query)
            length = struct.unpack('!H', module.recv_exact(stream, 2))[0]
            response = module.recv_exact(stream, length)
    else:
        response, _, _ = udp_vless(module, port, '127.0.0.1', DNS_PORT, query)
    return dns_reply_ips(module, query, response)


def dns_reply_ips(module, query, response):
    # Real sites can have several A records, unlike the synthetic first pilot.
    require(len(response) >= 12 and response[:2] == query[:2], 'DNS_TRANSACTION_ID_INVALID')
    _, flags, questions, answers, _, _ = struct.unpack('!6H', response[:12])
    require(flags & 0x8000 and not flags & 0x0200 and flags & 15 == 0
            and questions == 1 and 0 < answers <= 64, 'DNS_RESPONSE_INVALID')
    _, offset = module.read_name(response, 12)
    offset += 4
    values = []
    for _ in range(answers):
        _, offset = module.read_name(response, offset)
        require(offset + 10 <= len(response), 'DNS_RECORD_TRUNCATED')
        kind, klass, _, length = struct.unpack('!HHIH', response[offset:offset + 10])
        offset += 10
        require(offset + length <= len(response), 'DNS_RECORD_DATA_TRUNCATED')
        if kind == 1 and klass == 1 and length == 4:
            values.append(socket.inet_ntoa(response[offset:offset + 4]))
        offset += length
    require(values, 'DNS_NO_IPV4_ANSWERS')
    return sorted(set(values))


def local_dns(module, name):
    query = module.dns_query(name)
    with socket.create_connection(('127.0.0.1', DNS_PORT), timeout=3) as stream:
        stream.sendall(struct.pack('!H', len(query)) + query)
        length = struct.unpack('!H', module.recv_exact(stream, 2))[0]
        response = module.recv_exact(stream, length)
    return dns_reply_ips(module, query, response)


def require_fake(values):
    require(len(values) == 1 and ipaddress.ip_address(values[0]) in FAKE_POOL,
            'EXPECTED_ONE_FAKE_IP')
    return values[0]


def require_real(values):
    require(all(ipaddress.ip_address(value).is_global
                and ipaddress.ip_address(value) not in FAKE_POOL for value in values),
            'EXPECTED_PUBLIC_REAL_IPS')


def udp_vless(module, port, address, destination_port, payload):
    control, relay, relay_port = module.socks_request(port, 3, '0.0.0.0', 0)
    with control, socket.socket(type=socket.SOCK_DGRAM) as stream:
        require(relay in ('0.0.0.0', '127.0.0.1'), 'CLIENT_UDP_RELAY_NOT_LOCAL')
        stream.settimeout(4)
        stream.connect(('127.0.0.1', relay_port))
        packet = b'\x00\x00\x00\x01' + socket.inet_aton(address)
        packet += struct.pack('!H', destination_port) + payload
        stream.send(packet)
        response = stream.recv(4096)
        require(len(response) >= 10 and response[:4] == b'\x00\x00\x00\x01',
                'VLESS_UDP_REPLY_INVALID')
        ip = socket.inet_ntoa(response[4:8])
        reply_port = struct.unpack('!H', response[8:10])[0]
        require(ip == address and reply_port == destination_port, 'VLESS_UDP_RETURN_MAPPING_INVALID')
        return response[10:], ip, reply_port


def parse_stun(data, transaction):
    require(len(data) >= 20, 'STUN_REPLY_SHORT')
    kind, size, cookie = struct.unpack('!HHI', data[:8])
    require(kind == 0x0101 and cookie == 0x2112a442
            and data[8:20] == transaction and len(data) >= 20 + size, 'STUN_HEADER_INVALID')
    offset = 20
    while offset + 4 <= 20 + size:
        kind, length = struct.unpack('!HH', data[offset:offset + 4])
        offset += 4
        require(offset + length <= 20 + size, 'STUN_ATTRIBUTE_TRUNCATED')
        if kind == 0x0020 and length == 8 and data[offset + 1] == 1:
            ip = bytes(a ^ b for a, b in zip(data[offset + 4:offset + 8],
                                            struct.pack('!I', 0x2112a442)))
            return socket.inet_ntoa(ip)
        offset += (length + 3) & ~3
    raise TrialError('STUN_IPV4_MAPPING_MISSING')


def stun_socks(module, port, fake_ip):
    last = None
    for _ in range(3):
        transaction = secrets.token_bytes(12)
        packet = struct.pack('!HHI', 1, 0, 0x2112a442) + transaction
        try:
            response, _, _ = udp_vless(module, port, fake_ip, 19302, packet)
            require(parse_stun(response, transaction) == PUBLIC_IP, 'STUN_PUBLIC_IP_MISMATCH')
            return
        except (OSError, TrialError) as error:
            if isinstance(error, TrialError) and str(error) == 'INTERRUPTED':
                raise
            last = error
    raise TrialError('FAKE_IP_UDP_STUN_FAILED') from last


def check_closed_destination(module, port, address, destination_port):
    stream, _, _ = module.socks_request(port, 1, address, destination_port)
    with stream:
        stream.settimeout(2)
        stream.sendall(b'\x05\x01\x00')
        try:
            value = stream.recv(2)
        except ConnectionResetError:
            value = b''
        except socket.timeout:
            raise TrialError('BLOCKED_DESTINATION_DID_NOT_CLOSE')
        require(not value, 'BLOCKED_DESTINATION_ACCEPTED')


