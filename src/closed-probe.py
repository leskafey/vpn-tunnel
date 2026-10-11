"""Verified helper functions; historical entrypoints excluded."""
import argparse


import copy


import fcntl


import hashlib


import http.client


import json


import os


from pathlib import Path


import secrets


import signal


import socket


import ssl


import stat


import subprocess


import sys


import time


import traceback


class ActivationError(Exception):
    pass


def require(value, code):
    if not value:
        raise ActivationError(code)


def closed_destination(helper, port, address, destination_port=443):
    started = time.monotonic()
    stream, _, _ = helper.socks_request(port, 1, address, destination_port)
    with stream:
        stream.settimeout(10)
        outcome = 'remote_eof'
        try:
            stream.sendall(b'\x05\x01\x00')
            data = stream.recv(2)
        except (ConnectionResetError, BrokenPipeError):
            data, outcome = b'', 'connection_reset'
        except socket.timeout:
            raise ActivationError('REJECTED_DESTINATION_DID_NOT_CLOSE') from None
        require(not data, 'REJECTED_DESTINATION_RETURNED_DATA')
    return {'outcome': outcome, 'seconds': round(time.monotonic() - started, 3), 'received_bytes': 0}


