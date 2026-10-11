"""Verified helper functions; historical entrypoints excluded."""
import collections


import hashlib


import ipaddress


import json


import os


from pathlib import Path


import platform


import re


import resource


import signal


import sys


import tempfile


import time


import urllib.error


import urllib.request


LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


SIMPLE_ADBLOCK = re.compile(r"(@@)?\|\|([^\s^$|]+)\^\Z")


def domain(value):
    value = value.lower().rstrip(".")
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = value.split(".")
    if (len(value) > 253 or len(labels) < 2 or labels[-1].isdigit()
            or not all(LABEL.fullmatch(label) for label in labels)):
        return None
    return value


def classify(line, kind):
    line = line.strip().lstrip("\ufeff")
    if not line or line.startswith(("#", "!", "[Adblock")):
        return "comment", None
    if kind == "adblock":
        match = SIMPLE_ADBLOCK.fullmatch(line)
        if not match:
            return "complex_exception" if line.startswith("@@") else "complex_rule", None
        name = domain(match.group(2))
        return ("allow" if match.group(1) else "block", name) if name else ("invalid", None)
    if line.startswith("*."):
        name = domain(line[2:])
        return ("wildcard", name) if name else ("invalid", None)
    name = domain(line)
    return ("domain", name) if name else ("invalid", None)


