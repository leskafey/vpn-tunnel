"""Verified helper functions; historical entrypoints excluded."""
from contextlib import ExitStack


import fcntl


import hashlib


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


class PilotError(Exception):
    pass


def require(value, code):
    if not value:
        raise PilotError(code)


class MockDNS(socketserver.BaseRequestHandler):
    helper = None

    def handle(self):
        query, stream = self.request
        try:
            _, end = self.helper.read_name(query, 12)
            kind, klass = struct.unpack('!HH', query[end:end + 4])
            count = int(kind == 1 and klass == 1)
            answer = (b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, 4)
                      + socket.inet_aton('127.0.0.1')) if count else b''
            response = query[:2] + struct.pack('!5H', 0x8180, 1, count, 0, 0)
            stream.sendto(response + query[12:end + 4] + answer, self.client_address)
        except (ValueError, struct.error, self.helper.PilotError):
            return


def check_dns_answer(result, expected, label, protocol):
    # The pinned wire helper validates one A record and returns an IP STRING.
    require(isinstance(result, str), 'DNS_HELPER_RESULT_TYPE_INVALID')
    try:
        address = ipaddress.IPv4Address(result)
    except ipaddress.AddressValueError:
        raise PilotError('DNS_HELPER_RESULT_ADDRESS_INVALID') from None
    actual = ('fake' if address in ipaddress.ip_network('198.18.0.0/16')
              else 'real' if result == '127.0.0.1' else 'other')
    if actual != expected:
        print('PERSONAL_DNS_MISMATCH=' + json.dumps({'case': label, 'protocol': protocol,
              'expected': expected, 'actual': actual,
              'answer': result if actual in ('fake', 'real') else 'withheld'}), flush=True)
    require(actual == expected, 'DNS_PRIORITY_MISMATCH:' + label + ':' + protocol)
    return result


