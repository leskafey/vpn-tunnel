"""Verified helper functions; historical entrypoints excluded."""
import hashlib


import json


from pathlib import Path


import re


import signal


import urllib.parse


import urllib.request


from types import SimpleNamespace


IANA = 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'


FILES = {'extra-proxy': 'include-hosts.txt', 'extra-direct': 'exclude-hosts.txt'}


CAP = 262144


class ExtrasError(Exception):
    pass


def require(value, code):
    if not value:
        raise ExtrasError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def allowed_url(url):
    value = urllib.parse.urlsplit(url)
    require(value.scheme == 'https' and value.hostname in
            ('data.iana.org',)
            and value.port in (None, 443) and value.username is None and value.password is None,
            'EXTRA_SOURCE_URL_NOT_ALLOWED')


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        allowed_url(new_url)
        return super().redirect_request(request, response, code, message, headers, new_url)


def deadline(_signum, _frame):
    raise ExtrasError('EXTRA_DOWNLOAD_TIMEOUT')


def download(url):
    allowed_url(url)
    request = urllib.request.Request(url, headers={'User-Agent': 'personal-vpn-domain-extras/1',
                                                 'Accept-Encoding': 'identity'})
    old_handler = signal.signal(signal.SIGALRM, deadline)
    require(signal.alarm(0) == 0, 'NESTED_SOURCE_DOWNLOAD_NOT_ALLOWED')
    signal.alarm(45)
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect())
        with opener.open(request, timeout=15) as response:
            require(response.status == 200, 'EXTRA_HTTP_STATUS_INVALID')
            allowed_url(response.geturl())
            require('html' not in response.headers.get('Content-Type', '').lower(), 'EXTRA_SOURCE_IS_HTML')
            raw = response.read(CAP + 1)
        require(0 < len(raw) <= CAP, 'EXTRA_SOURCE_SIZE_INVALID')
        return raw
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


def delegated_tlds(raw):
    require(0 < len(raw) <= 65536, 'IANA_SOURCE_SIZE_INVALID')
    rows = raw.decode('ascii').splitlines()
    require(rows and re.fullmatch(r'# Version \d{10}, Last Updated .+', rows[0]), 'IANA_HEADER_INVALID')
    names = rows[1:]
    require(1000 <= len(names) <= 2500 and len(set(names)) == len(names)
            and all(re.fullmatch(r'[A-Z][A-Z0-9-]{0,62}', name) for name in names), 'IANA_TLD_LIST_INVALID')
    return frozenset(name.lower() for name in names)


def parse(raw, parser, tlds):
    require(0 < len(raw) <= CAP, 'EXTRA_SOURCE_SIZE_INVALID')
    roots, zones = set(), set()
    valid = 0
    for row in raw.decode('utf-8-sig').splitlines():
        require(len(row.encode('utf-8')) <= 4096, 'EXTRA_LINE_TOO_LONG')
        category, domain = parser.classify(row, 'domains')
        if category == 'comment':
            continue
        if domain:
            require(category in ('domain', 'wildcard'), 'EXTRA_DOMAIN_CATEGORY_INVALID')
        else:
            value = row.strip().lower().rstrip('.')
            if value.startswith('*.'):
                value = value[2:]
            try:
                value = value.encode('idna').decode('ascii')
            except UnicodeError:
                value = ''
            require(value in tlds, 'EXTRA_INVALID_DOMAIN_OR_UNDELEGATED_TLD')
            domain = value
            zones.add(domain)
        valid += 1
        roots.add(domain)
    require(0 < len(roots) <= 10000 and len(zones) <= 64, 'EXTRA_DOMAIN_COUNT_INVALID')
    return roots, zones, valid


def covered(name, roots):
    labels = name.split('.')
    return any('.'.join(labels[index:]) in roots for index in range(len(labels)))


def no_lost_coverage(old, fresh):
    lost = sum(not covered(name, fresh) for name in old)
    require(lost == 0, 'EXTRA_SUFFIX_COVERAGE_REMOVED_REVIEW_REQUIRED')

