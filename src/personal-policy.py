#!/usr/bin/env python3
"""Small server-side personal domain policy; no runtime changes on import."""
import json

MAX_FILE_BYTES = 65536
MAX_ENTRIES = 2048
KEYS = ('proxy', 'direct', 'ads-exceptions', 'ads')
BASE_FILTERS = ['RULE-SET,ads,fake-ip', 'RULE-SET,direct,real-ip',
                'DOMAIN,api.ipify.org,fake-ip', 'DOMAIN,stun.l.google.com,fake-ip',
                'RULE-SET,smart,fake-ip', 'MATCH,real-ip']


class PolicyError(Exception):
    """Fixed error codes only: never echo personal domains or input lines."""


def require(value, code):
    if not value:
        raise PolicyError(code)


def parse_personal(raw, parser):
    require(isinstance(raw, bytes) and len(raw) <= MAX_FILE_BYTES, 'PERSONAL_FILE_SIZE_LIMIT')
    try:
        text = raw.decode('utf-8')
    except UnicodeError:
        raise PolicyError('PERSONAL_FILE_ENCODING_INVALID') from None
    entries = set()
    for row in text.splitlines():
        require(len(row.encode('utf-8')) <= 4096, 'PERSONAL_LINE_SIZE_LIMIT')
        category, name = parser.classify(row, 'domains')
        if category == 'comment':
            continue
        require(category in ('domain', 'wildcard') and isinstance(name, str), 'PERSONAL_DOMAIN_INVALID')
        # Preserve the existing personal-file contract: root and descendants.
        entries.add(name)
        require(len(entries) <= MAX_ENTRIES, 'PERSONAL_ENTRY_COUNT_LIMIT')
    return sorted(entries)


def line_value(text, prefix):
    rows = [row[len(prefix):] for row in text.splitlines() if row.startswith(prefix)]
    require(len(rows) == 1, 'POLICY_FIELD_MISSING_OR_DUPLICATE')
    return json.loads(rows[0])


def replace_line(text, prefix, value):
    rows = text.splitlines()
    indices = [index for index, row in enumerate(rows) if row.startswith(prefix)]
    require(len(indices) == 1, 'POLICY_FIELD_MISSING_OR_DUPLICATE')
    rows[indices[0]] = prefix + json.dumps(value)
    return '\n'.join(rows) + '\n'


def compose(baseline, personal):
    """Return config and exact expected inline counts; do not write any files.

    Ads remain first; exceptions suppress only ads. Routing precedence then is
    personal direct, personal proxy, automatic direct, automatic proxy, default.
    A classical predicate provider wraps AND/NOT because top-level logical rules
    are disallowed in this pinned runtime's fake-ip-filter.
    """
    # Old generations do not have a personal advertising blocklist yet.
    require(set(personal) in (set(KEYS), set(KEYS) - {'ads'}), 'PERSONAL_SET_INVALID')
    personal = dict(personal, ads=personal.get('ads', []))
    for names in personal.values():
        require(isinstance(names, list) and len(names) <= MAX_ENTRIES
                and names == sorted(set(names)) and all(isinstance(name, str) for name in names),
                'PERSONAL_NORMALIZED_SET_INVALID')
    providers = line_value(baseline, 'rule-providers: ')
    require(isinstance(providers, dict) and {'smart', 'direct', 'ads'} <= set(providers)
            and set(providers) <= {'smart', 'direct', 'ads', 'ads-allow', 'ads-important'},
            'BASE_PROVIDER_SET_CHANGED')
    require(line_value(baseline, '  fake-ip-filter: ') == BASE_FILTERS, 'BASE_DNS_PRIORITY_CHANGED')
    require(baseline.count('  - RULE-SET,ads,REJECT\n') == 1
            and baseline.count('  - MATCH,DIRECT\n') == 1, 'BASE_DESTINATION_RULES_CHANGED')
    counts = {}
    tags = {'proxy': 'personal-proxy', 'direct': 'personal-direct', 'ads-exceptions': 'ads-exceptions',
            'ads': 'personal-ads'}
    for key, tag in tags.items():
        if personal[key]:
            providers[tag] = {'type': 'inline', 'behavior': 'domain',
                              'payload': ['+.' + name for name in personal[key]]}
            counts[tag] = len(personal[key])
    ad_tag = 'ads'
    # Upstream exceptions apply to ordinary automatic rules. Explicit personal
    # blocks and AdGuard $important rules can override them. Personal exceptions
    # are the final user override and never choose DIRECT/PROXY on their own.
    predicate = 'RULE-SET,ads'
    if 'ads-allow' in providers:
        predicate = 'AND,((RULE-SET,ads),(NOT,((RULE-SET,ads-allow))))'
    alternatives = [predicate]
    if 'ads-important' in providers:
        alternatives.append('RULE-SET,ads-important')
    if personal['ads']:
        alternatives.append('RULE-SET,personal-ads')
    if len(alternatives) > 1:
        predicate = 'OR,(' + ','.join('(' + rule + ')' for rule in alternatives) + ')'
    if personal['ads-exceptions']:
        predicate = 'AND,((' + predicate + '),(NOT,((RULE-SET,ads-exceptions))))'
    if predicate != 'RULE-SET,ads':
        ad_tag = 'ads-effective'
        providers[ad_tag] = {'type': 'inline', 'behavior': 'classical',
                            'payload': [predicate]}
        counts[ad_tag] = 1
    filters = ['RULE-SET,' + ad_tag + ',fake-ip']
    for key, action in (('direct', 'real-ip'), ('proxy', 'fake-ip')):
        if personal[key]:
            filters.append('RULE-SET,' + tags[key] + ',' + action)
    filters += BASE_FILTERS[1:]
    text = replace_line(baseline, '  fake-ip-filter: ', filters)
    text = replace_line(text, 'rule-providers: ', providers)
    text = text.replace('  - RULE-SET,ads,REJECT\n', '  - RULE-SET,' + ad_tag + ',REJECT\n', 1)
    return text, counts
