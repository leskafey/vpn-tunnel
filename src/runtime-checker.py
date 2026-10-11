"""Verified helper functions; historical entrypoints excluded."""
from contextlib import closing


import fcntl


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


import socketserver


import struct


import subprocess


import sys


import time


import traceback


SOURCE = None


TAGS = ('smart', 'direct', 'ads')


FAKE_POOL = ipaddress.ip_network('198.18.0.0/16')


class CheckError(Exception):
    pass


def require(value, code):
    if not value:
        raise CheckError(code)


def replace_line(text, prefix, replacement):
    rows = text.splitlines()
    found = [index for index, row in enumerate(rows) if row.startswith(prefix)]
    require(len(found) == 1, 'BASELINE_FIELD_MISSING_OR_DUPLICATE')
    rows[found[0]] = replacement
    return '\n'.join(rows) + '\n'


def suffix_roots(path):
    roots = set()
    with path.open(encoding='ascii') as stream:
        for row in stream:
            require(row.endswith('\n') and row.startswith('+.'), 'APEX_SUFFIX_PATTERN_REQUIRED')
            roots.add(row[2:-1])
    return roots


def within(name, roots):
    labels = name.split('.')
    return any('.'.join(labels[index:]) in roots for index in range(len(labels)))


def witnesses():
    direct = suffix_roots(SOURCE / 'direct.normalized.txt')
    ads = suffix_roots(SOURCE / 'ads.normalized.txt')
    require(direct and ads, 'DIRECT_AND_ADS_WITNESSES_REQUIRED')
    forbidden = direct | ads
    public = ('instagram.com', 'www.instagram.com', 'i.instagram.com', 'graph.instagram.com')
    public_matches = set()
    root = None
    with (SOURCE / 'smart.normalized.txt').open(encoding='ascii') as stream:
        for row in stream:
            require(row.startswith('+.') and row.endswith('\n'), 'SMART_SUFFIX_POLICY_REQUIRED')
            name = row[2:-1]
            if root is None and len(name) <= 180 and not within(name, forbidden):
                root = name
            for domain in public:
                if domain == name or domain.endswith('.' + name):
                    public_matches.add(domain)
    require(root is not None and public_matches == set(public), 'SMART_APEX_CHILD_WITNESSES_MISSING')
    require(not any(within(domain, forbidden) for domain in public), 'PUBLIC_WITNESS_PRIORITY_CONFLICT')
    direct_root = next((name for name in sorted(direct) if len(name) <= 180 and not within(name, ads)), None)
    ad_root = next((name for name in sorted(ads) if len(name) <= 180), None)
    require(direct_root and ad_root, 'BOUNDED_WITNESSES_REQUIRED')
    token = 'vpn-check-' + secrets.token_hex(4)
    return {'apex': root, 'child': token + '.' + root, 'deep-child': 'deep.' + token + '.' + root,
            'direct-apex': direct_root, 'direct-child': token + '.' + direct_root,
            'ads-child': token + '.' + ad_root, 'default': token + '.invalid',
            'stress-root': root, 'public_names': public}


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=3)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def loaded_counts(path, expected):
    with closing(UnixHTTP(path)) as client:
        client.request('GET', '/providers/rules')
        response = client.getresponse()
        require(response.status == 200, 'PROVIDER_API_UNAVAILABLE')
        raw = response.read(65537)
        require(len(raw) <= 65536, 'PROVIDER_RESPONSE_TOO_LARGE')
    providers = json.loads(raw).get('providers')
    require(isinstance(providers, dict) and set(providers) == set(expected), 'PROVIDERS_NOT_READY')
    counts = {tag: providers[tag].get('ruleCount') for tag in expected}
    require(all(type(counts[tag]) is int and counts[tag] == expected[tag] for tag in expected),
            'PROVIDERS_NOT_FULLY_LOADED')
    return counts


def rss(pid):
    result = {}
    for row in Path('/proc', str(pid), 'status').read_text().splitlines():
        if row.startswith(('VmHWM:', 'VmRSS:')):
            result[row.split(':')[0] + '_MiB'] = round(int(row.split()[1]) / 1024, 2)
    return result


def stop_process(process):
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
    process.wait(timeout=5)


def reject_destination(helper, port, address):
    stream, _, _ = helper.socks_request(port, 1, address, 443)
    with stream:
        stream.settimeout(5)
        stream.sendall(b'\x05\x01\x00')
        try:
            data = stream.recv(2)
        except ConnectionResetError:
            data = b''
        require(not data, 'ADVERTISEMENT_DESTINATION_ACCEPTED')


