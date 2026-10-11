"""Verified helper functions; historical entrypoints excluded."""
import fcntl


import hashlib


import importlib.util


import itertools


import json


import os


from pathlib import Path


import platform


import re


import resource


import shutil


import signal


import subprocess


import sys


import time


import traceback


import urllib.request


import uuid


from datetime import datetime, timezone


NAMES = ('rulist', 'antifilter', 'extra-proxy', 'extra-direct', 'oisd-small')


LIMITS = {'rulist': (500000, 4000000), 'antifilter': (500000, 4000000),
          'extra-proxy': (500, 10000), 'extra-direct': (1, 1000), 'oisd-small': (30000, 200000)}


STEP = 'start'


class BuildError(Exception):
    """Messages contain fixed codes only, never source URLs or personal domains."""


def require(value, code):
    if not value:
        raise BuildError(code)


def step(label):
    global STEP
    STEP = label
    print('TEXT_POLICY_STEP=' + label, flush=True)


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(65536), b''):
            value.update(block)
    return value.hexdigest()


def atomic_json(path, value):
    temporary = path.with_name('.' + path.name + '-' + uuid.uuid4().hex)
    with temporary.open('x') as output:
        json.dump(value, output, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def native(arguments, label, work, timeout=180):
    step(label)
    updater_idle()
    started = time.monotonic()
    next_check = started + 15
    with (work / (label + '.private.log')).open('xb') as output:
        process = subprocess.Popen([str(arg) for arg in arguments], stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True,
                                   env=dict(os.environ, LC_ALL='C', GOMEMLIMIT='256MiB',
                                            GOGC='50', GOMAXPROCS='1'))
        try:
            while process.poll() is None:
                now = time.monotonic()
                require(now - started < timeout, 'PROCESS_TIMEOUT')
                if now >= next_check:
                    updater_idle()
                    print('TEXT_POLICY_PROGRESS=' + json.dumps({'phase': label,
                          'seconds': round(now - started, 1)}), flush=True)
                    next_check = now + 15
                time.sleep(0.25)
            if process.returncode != 0:
                print('TEXT_PROCESS_FAILURE=' + json.dumps({'phase': label, 'exit_code': process.returncode,
                      'seconds': round(time.monotonic() - started, 2)}), flush=True)
                raise BuildError('NATIVE_PROCESS_FAILED')
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=10)
    print('TEXT_PROCESS_OK=' + label + '; seconds=' + str(round(time.monotonic() - started, 2)), flush=True)


def download(url, destination):
    require(isinstance(url, str) and url.startswith('https://'), 'HTTPS_SOURCE_REQUIRED')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers={'User-Agent': 'personal-vpn-text-policy/1',
                                                  'Accept-Encoding': 'identity'})
    total = 0
    next_progress = time.monotonic() + 15
    signal.alarm(120)
    try:
        with opener.open(request, timeout=20) as response, destination.open('xb') as output:
            require(response.status == 200 and response.geturl().startswith('https://'),
                    'SOURCE_HTTP_STATUS_INVALID')
            require('html' not in response.headers.get('Content-Type', '').lower(), 'SOURCE_IS_HTML')
            for block in iter(lambda: response.read(65536), b''):
                total += len(block)
                require(total <= 64 * 1048576, 'SOURCE_SIZE_LIMIT')
                output.write(block)
                if time.monotonic() >= next_progress:
                    updater_idle()
                    print('TEXT_POLICY_PROGRESS=' + json.dumps({'phase': STEP, 'downloaded_bytes': total}), flush=True)
                    next_progress = time.monotonic() + 15
        require(total > 0, 'SOURCE_EMPTY')
    finally:
        signal.alarm(0)
    return {'bytes': total, 'sha256': digest(destination)}


def source_deadline(_signal, _frame):
    raise BuildError('SOURCE_DOWNLOAD_TIMEOUT')


def guard_count(name, count, discarded, baseline):
    low, high = LIMITS[name]
    require(low <= count <= high and discarded <= max(10, count * 0.005), 'SOURCE_COUNT_OR_FORMAT_GUARD')
    require(type(baseline) is int and baseline > 0, 'SOURCE_BASELINE_INVALID')
    require(baseline * 0.75 <= count <= baseline * 1.25, 'SOURCE_CHANGE_OVER_25_PERCENT')


def normalize_source(parser, name, source, destination, baseline):
    count = discarded = 0
    next_progress = time.monotonic() + 15
    with source.open(encoding='utf-8') as data, destination.open('x', encoding='ascii') as output:
        while True:
            row = data.readline(4097)
            if not row:
                break
            require(len(row) <= 4096, 'SOURCE_LINE_TOO_LONG')
            category, domain = parser.classify(row, 'domains')
            if domain:
                require(category in ('domain', 'wildcard'), 'SOURCE_CATEGORY_INVALID')
                require(category != 'wildcard' or name not in ('rulist', 'antifilter'),
                        'UNEXPECTED_REGISTRY_WILDCARD')
                output.write(domain + '\n')
                count += 1
            elif category != 'comment':
                discarded += 1
            now = time.monotonic()
            if now >= next_progress:
                updater_idle()
                print('TEXT_POLICY_PROGRESS=' + json.dumps({'phase': 'normalize-' + name,
                      'valid_so_far': count}), flush=True)
                next_progress = now + 15
    guard_count(name, count, discarded, baseline)
    return {'valid': count, 'discarded': discarded}


def pattern_rows(path):
    with path.open(encoding='ascii') as source:
        for row in source:
            require(row.endswith('\n') and row != '\n', 'PATTERN_LINE_INVALID')
            yield row[:-1]


def event_rows(patterns):
    for pattern in patterns:
        if pattern.startswith('+.'):
            name, kinds = pattern[2:], ('E', 'S')
        elif pattern.startswith('.'):
            name, kinds = pattern[1:], ('S',)
        else:
            name, kinds = pattern, ('E',)
        require(re.fullmatch(r'[a-z0-9_-]+(?:\.[a-z0-9_-]+)*', name) is not None,
                'DOMAIN_PATTERN_NOT_SUPPORTED')
        key = name[::-1] + '.'
        for kind in kinds:
            yield key + '\t' + kind + '\n'


def reduce_events(rows):
    ancestor = previous_key = None
    records = (row.rstrip('\n').split('\t') for row in rows)
    for key, group in itertools.groupby(records, key=lambda item: item[0]):
        require(previous_key is None or previous_key < key, 'DOMAIN_EVENTS_NOT_SORTED')
        previous_key = key
        kinds = {item[1] for item in group}
        require(kinds and kinds <= {'E', 'S'} and key.endswith('.'), 'DOMAIN_EVENT_INVALID')
        if ancestor is not None and key.startswith(ancestor):
            continue
        ancestor = None
        name = key[:-1][::-1]
        if 'S' in kinds:
            ancestor = key
            yield ('+.' if 'E' in kinds else '.') + name
        else:
            yield name


def sorted_unique(source, destination, work, label):
    native(['/usr/bin/sort', '-u', '--buffer-size=32M', '--parallel=1',
            '--temporary-directory=' + str(work), '-o', destination, source], label, work)


def normalized(source, destination, work, label):
    raw = work / (label + '.events')
    ordered = work / (label + '.events.sorted')
    with raw.open('x', encoding='ascii') as output:
        output.writelines(event_rows(pattern_rows(source)))
    sorted_unique(raw, ordered, work, label)
    count = 0
    with ordered.open(encoding='ascii') as events, destination.open('x', encoding='ascii') as output:
        for pattern in reduce_events(events):
            output.write(pattern + '\n')
            count += 1
    return count


def promote_registry(source, destination):
    count = rewritten = 0
    with destination.open('x', encoding='ascii') as output:
        for name in pattern_rows(source):
            require(not name.startswith('.'), 'REGISTRY_MUST_CONTAIN_EXACT_NAMES')
            output.write('+.' + name + '\n')
            count += 1
            parent = re.sub(r'^(?:[0-9]*www[0-9]*|hd[0-9]*|[0-9]+)\.(?=.+\.)', '', name, count=1)
            if parent != name:
                output.write('+.' + parent + '\n')
                rewritten += 1
    return count, rewritten


def append_suffixes(source, output):
    count = 0
    for name in pattern_rows(source):
        output.write('+.' + name + '\n')
        count += 1
    return count


def equal_files(first, second):
    if first.stat().st_size != second.stat().st_size:
        return False
    with first.open('rb') as a, second.open('rb') as b:
        while True:
            left, right = a.read(65536), b.read(65536)
            if left != right:
                return False
            if not left:
                return True


def compile_and_verify(tag, raw, assets, work):
    before = work / (tag + '.normalized.txt')
    count = normalized(raw, before, work, 'normalize-' + tag)
    require(count > 0, 'EMPTY_DOMAIN_PROVIDER')
    binary = assets / (tag + '.mrs')
    native([MIHOMO, 'convert-ruleset', 'domain', 'text', before, binary], 'compile-' + tag, work)
    recovered = work / (tag + '.roundtrip.txt')
    native([MIHOMO, 'convert-ruleset', 'domain', 'mrs', binary, recovered], 'roundtrip-' + tag, work)
    after = work / (tag + '.roundtrip.normalized.txt')
    normalized(recovered, after, work, 'validate-' + tag)
    require(equal_files(before, after), 'FULL_DOMAIN_SEMANTIC_ROUNDTRIP_MISMATCH')
    print('TEXT_MRS_FULL_COVERAGE_OK=' + tag, flush=True)
    return {'sha256': digest(binary), 'bytes': binary.stat().st_size, 'behavior': 'domain',
            'normalized_patterns': count, 'semantic_witness_sha256': digest(before),
            'coverage_roundtrip': 'passed'}


