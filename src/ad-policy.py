"""Bounded DNS advertising sources; unsupported URL rules are never widened."""
import ipaddress
import re


ADGUARD_URL = 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt'
EXTRA_FILES = {'antizapret-ads': 'include-adblock-hosts.txt',
               'antizapret-ads-allow': 'exclude-adblock-hosts.txt'}
DOMAIN_RULE = re.compile(r'(@@)?\|\|([^\s^$|/?:]+)\^\|?(?:\$((?:important|badfilter)(?:,(?:important|badfilter))*))?\Z')
EXACT_ALLOW = re.compile(r'@@\|([^\s^$|/?:]+)\^\|(?:\$((?:important|badfilter)(?:,(?:important|badfilter))*))?\Z')
LIMITS = {'adguard-dns': (10000, 1000000), 'antizapret-ads': (0, 10000),
          'antizapret-ads-allow': (0, 10000)}


class AdPolicyError(Exception):
    pass


def require(value, code):
    if not value:
        raise AdPolicyError(code)


def normalize(parser, name, source, work, previous=None):
    """Return separate block/allow/important suffixes, honoring $badfilter.

    Regex, embedded wildcards and request/URL patterns cannot be represented by
    a DNS domain provider. Count them explicitly and cap their share; never
    strip a path or an unknown modifier and block the resulting whole domain.
    """
    rules, disabled = {}, set()
    count = unsupported = 0
    with source.open(encoding='utf-8') as stream:
        while True:
            raw = stream.readline(4097)
            if not raw:
                break
            require(len(raw) <= 4096, 'ADS_SOURCE_LINE_TOO_LONG')
            row = raw.strip().lstrip('\ufeff')
            if not row or row.startswith(('#', '!', '[Adblock')):
                continue
            count += 1
            if name == 'adguard-dns':
                exact = EXACT_ALLOW.fullmatch(row)
                match = DOMAIN_RULE.fullmatch(row)
                if not exact and not match:
                    unsupported += 1
                    continue
                allow, host, modifiers = (True, *exact.groups()) if exact else match.groups()
                options = modifiers.split(',') if modifiers else []
                if len(options) != len(set(options)) or '*' in host or allow and 'important' in options:
                    unsupported += 1
                    continue
                domain = parser.domain(host)
                if domain is None:
                    try:
                        ipaddress.ip_address(host)
                    except ValueError:
                        pass
                    else:
                        unsupported += 1
                        continue
                require(domain is not None, 'ADS_SOURCE_DOMAIN_INVALID')
                kind = 'allow' if allow else 'important' if 'important' in options else 'block'
                # badfilter refers to source text, before domain normalization or
                # deduplication of DNS patterns (AdGuard DNS syntax specification).
                pattern = row.split('$', 1)[0]
                remaining = [option for option in options if option != 'badfilter']
                identity = pattern + ('$' + ','.join(remaining) if remaining else '')
                if 'badfilter' in options:
                    disabled.add(identity)
                else:
                    rules[identity] = (kind, domain, bool(exact))
            else:
                category, domain = parser.classify(row, 'domains')
                require(category in ('domain', 'wildcard') and domain is not None, 'ADS_SOURCE_DOMAIN_INVALID')
                rules[row] = ('allow' if name == 'antizapret-ads-allow' else 'block', domain, False)
    low, high = LIMITS[name]
    require(low <= count <= high and unsupported <= max(10, count * .05), 'ADS_SOURCE_COUNT_OR_FORMAT_GUARD')
    if previous is not None:
        baseline = previous['valid']
        require(type(baseline) is int and baseline >= 0, 'ADS_SOURCE_BASELINE_INVALID')
        require(abs(count - baseline) <= max(10, baseline * .25), 'ADS_SOURCE_CHANGE_OVER_25_PERCENT')
    effective = {(kind, domain if exact else '+.' + domain)
                 for identity, (kind, domain, exact) in rules.items() if identity not in disabled}
    paths = {}
    for kind in ('block', 'allow', 'important'):
        path = work / (name + '.' + kind + '.txt')
        path.write_text(''.join(pattern + '\n' for k, pattern in sorted(effective) if k == kind), encoding='ascii')
        paths[kind] = path
    return paths, {'valid': count, 'unsupported': unsupported, 'disabled': len(rules.keys() & disabled),
                   **{kind: sum(k == kind for k, _ in effective) for kind in paths}}


def build(s, work, commit, previous=None):
    """Combine the existing OISD source with AdGuard and pinned AntiZapret lists."""
    blocks = [work / 'oisd-small.unique.txt']
    allows, important = [], []
    metadata = {}
    sources = {'adguard-dns': ADGUARD_URL,
               **{name: s.extras.BASE + commit + '/setup/root/antizapret/download/' + filename
                  for name, filename in EXTRA_FILES.items()}}
    for name, url in sources.items():
        raw = work / (name + '.source.txt')
        info = s.builder.download(url, raw)
        paths, counts = normalize(s.parser, name, raw, work,
                                  previous.get('source_metadata', {}).get(name) if previous else None)
        metadata[name] = dict(info, **counts)
        blocks.append(paths['block'])
        allows.append(paths['allow'])
        important.append(paths['important'])
    tags = []
    for tag, paths in (('ads', blocks), ('ads-allow', allows), ('ads-important', important)):
        destination = work / (tag + '.raw.txt')
        with destination.open('x', encoding='ascii') as output:
            for path in paths:
                with path.open(encoding='ascii') as incoming:
                    for row in incoming:
                        output.write(row if path.name != 'oisd-small.unique.txt' else '+.' + row)
        if destination.stat().st_size:
            tags.append(tag)
    return tags, metadata
