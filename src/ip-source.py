"""Verified helper functions; historical entrypoints excluded."""
from contextlib import ExitStack


from datetime import datetime, timezone


import fcntl


import hashlib


import importlib.util


import ipaddress


import json


import os


from pathlib import Path


import re


import secrets


import subprocess


import sys


import traceback


import urllib.parse


import urllib.request


SOURCE_LIMIT = 16384


ALLOWED_HOSTS = {'api.github.com', 'raw.githubusercontent.com', 'core.telegram.org'}


class CandidateError(Exception):
    pass


def require(value, code):
    if not value:
        raise CandidateError(code)


def allowed_url(url):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname in ALLOWED_HOSTS
            and parsed.port in (None, 443) and parsed.username is None and parsed.password is None,
            'SOURCE_URL_NOT_ALLOWED')


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        allowed_url(new_url)
        return super().redirect_request(request, response, code, message, headers, new_url)


def download(url):
    allowed_url(url)
    request = urllib.request.Request(url, headers={'User-Agent': 'personal-vpn-small-ip-policy/1',
                                                 'Accept': '*/*'})
    with urllib.request.build_opener(Redirect()).open(request, timeout=15) as response:
        require(response.status == 200, 'SOURCE_HTTP_STATUS')
        allowed_url(response.url)
        raw = response.read(SOURCE_LIMIT + 1)
    require(0 < len(raw) <= SOURCE_LIMIT, 'SOURCE_SIZE_LIMIT')
    return raw


def parse_source(raw, official=False):
    require(0 < len(raw) <= SOURCE_LIMIT, 'SOURCE_SIZE_LIMIT')
    ipv4, ipv6 = [], []
    for line in raw.decode('utf-8-sig').splitlines():
        row = line.split('#', 1)[0].strip()
        if not row:
            continue
        require(len(row) <= 64 and '/' in row and not any(char.isspace() for char in row),
                'SOURCE_LINE_FORMAT')
        try:
            network = ipaddress.ip_network(row, strict=True)
        except ValueError:
            raise CandidateError('SOURCE_INVALID_CIDR') from None
        require(network.is_global, 'SOURCE_NONPUBLIC_NETWORK')
        if network.version == 6:
            require(official and network.prefixlen >= 32, 'UNEXPECTED_IPV6_NETWORK')
            ipv6.append(network)
        else:
            require(network.prefixlen >= 12, 'SOURCE_NETWORK_TOO_BROAD')
            ipv4.append(network)
    require(1 <= len(ipv4) <= 256 and len(set(ipv4)) == len(ipv4)
            and len(set(ipv6)) == len(ipv6), 'SOURCE_EMPTY_OVERSIZED_OR_DUPLICATE')
    if official:
        require(7 <= len(ipv4) <= 12 and len(ipv6) <= 16
                and all(network.prefixlen >= 20 for network in ipv4), 'OFFICIAL_TELEGRAM_SOURCE_GUARD')
    return ipv4, ipv6


