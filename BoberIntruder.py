import base64
import urllib
from urlparse import urlparse
import re
import itertools

# ============================================================================================== #
#                                      EDITABLE CONTROL PANEL                                   #
# ============================================================================================== #
# This file is intentionally optimized for TurboIntruder panel editing:
# - most things that change often live here at the top
# - rules remain easy to comment/uncomment
# - runtime logic stays below in reusable helpers

# ------------------------------- PAYLOAD TRANSFORMER CONFIG ----------------------------------- #

TRANSFORMER_MODE = 'url_enc'
# TRANSFORMER_MODE = 'extensions'
# TRANSFORMER_MODE = 'base64'
# TRANSFORMER_MODE = 'custom'
# TRANSFORMER_MODE = 'none'

EXTENSIONS = ['.php', '']


def custom(word):
    combined = 'http://' + word + '/etc/passwd'
    encoded = base64.b64encode(combined)
    return [encoded]


def encode_base64(word):
    encoded_string = base64.b64encode(word.encode('utf-8')).decode('utf-8')
    return [encoded_string]


# ------------------------------- RESPONSE FILTER CONFIG --------------------------------------- #

# Return None when any enabled rule matches, otherwise accept.
EVALUATION_RULES = [
    # lambda s, w, l, r: w < 2225,
    lambda s, w, l, r: w == 106,
    lambda s, w, l, r: w == 223,
    # lambda s, w, l, r: w == 136,
    # lambda s, w, l, r: w == 167,
    # lambda s, w, l, r: s == 404,
    # lambda s, w, l, r: s == 360,
    # lambda s, w, l, r: l == 3803,
    # lambda s, w, l, r: l == 186,
    # lambda s, w, l, r: "Tell me a bit more" in r,
    # lambda s, w, l, r: "pick a room and say " in r,
    # lambda s, w, l, r: "Got it! You wrote: " in r,
]


# ------------------------------- PAYLOAD / REDIRECT EXCLUSIONS -------------------------------- #

EXCLUDED_PAYLOADS = ['logout']
EXCLUDED_LOCATIONS = ['/cacti', 'EveryTimeRedirectingUs.html']


# ------------------------------- RECURSION / REDIRECT SWITCHES -------------------------------- #

FOLLOW_REDIRECT = False
RECURSIVE = False
RECURSIVE_TO_ANY_HIT = False


# ------------------------------- WORDLIST / MARKER CONFIG ------------------------------------- #

PAYLOAD_LISTS = [
    # LIST1
    r'/usr/share/seclists/Discovery/Web-Content/big.txt',
    # LIST2
    # r'/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt',
    # LIST3
    # r'/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt',
    # LIST4
    # r'/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt',
    # LIST5
    # r'/usr/share/seclists/Passwords/500-worst-passwords.txt',
    # LIST6
    # r'/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt'
]

# Used only as a replacement skeleton for multi-payload attack modes.
DEFAULT_PAYLOAD_LIST = [
    'payload1',
    'payload2',
    'payload3',
    'payload4',
    'payload5',
    'payload6'
]

# Optional emergency fallback if external wordlists are unavailable.
FALLBACK_PAYLOAD_LISTS = [
    [
        'payload1',
        'payload2',
        'payload3',
        'payload4',
        'payload5',
        'payload6'
    ]
]


# ------------------------------- ATTACK MODE CONFIG ------------------------------------------- #

ATTACK_MODE = 'default'
# default       : single payloadmarker, using wordlist set 1
# sniper        : multiple payloadmarkers, testing one by one target
# battering_ram : same payload into all positions simultaneously
# pitchfork     : payload sets move in parallel by position
# cluster_bomb  : every combination of payload sets


# ------------------------------- REQUEST ENGINE CONFIG ---------------------------------------- #

ENGINE_CONFIG = {
    'concurrentConnections': 15,
    'requestsPerConnection': 1,
    'pipeline': False,
}


# ============================================================================================== #
#                                         RUNTIME LOGIC                                          #
# ============================================================================================== #

MODE1 = TRANSFORMER_MODE


def get_extensions():
    return EXTENSIONS


def transform_url_enc(word):
    return [urllib.quote(word)]


def transform_extensions(word):
    encoded = urllib.quote(word)
    return [encoded + ext for ext in get_extensions()]


def transform_base64(word):
    return encode_base64(word)


def transform_custom(word):
    return custom(urllib.quote(word))


TRANSFORMERS = {
    'url_enc': transform_url_enc,
    'extensions': transform_extensions,
    'base64': transform_base64,
    'custom': transform_custom,
    'none': lambda word: [word],
}


def transformer(word, mode='url_enc'):
    handler = TRANSFORMERS.get(mode)
    if handler is None:
        return [word]
    return handler(word)


def evaluate_request(status, wordcount, length, response):
    for pred in EVALUATION_RULES:
        try:
            if pred(status, wordcount, length, response):
                return None
        except Exception:
            return None
    return True


def is_excluded_payload(payload):
    return payload in EXCLUDED_PAYLOADS


def load_payload_sets():
    payload_sets = []

    for path in PAYLOAD_LISTS:
        try:
            with open(path) as f:
                loaded = [line.rstrip() for line in f if line.strip()]
                if loaded:
                    payload_sets.append(loaded)
        except Exception:
            continue

    if payload_sets:
        return payload_sets

    return FALLBACK_PAYLOAD_LISTS


def encode_for_request(payload):
    return urllib.quote(payload)


def transformed_payloads(payload, mode):
    return [t for t in transformer(payload, mode) if not is_excluded_payload(t)]


# ========== DEFAULT ==========
def _attack_default(engine, target, payload_sets, mode):
    for payload in payload_sets[0]:
        for transformed in transformed_payloads(payload, mode):
            engine.queue(target.req, transformed)


# ========== SNIPER ==========
def _attack_sniper(engine, target, payload_sets, mode):
    for index in range(len(DEFAULT_PAYLOAD_LIST)):
        for payload in payload_sets[0]:
            for transformed in transformed_payloads(payload, mode):
                req = DEFAULT_PAYLOAD_LIST[:]
                req[index] = encode_for_request(transformed)
                engine.queue(target.req, req)


# ========== BATTERING RAM ==========
def _attack_battering_ram(engine, target, payload_sets, mode):
    for payload in payload_sets[0]:
        for transformed in transformed_payloads(payload, mode):
            encoded = encode_for_request(transformed)
            req = [encoded] * len(DEFAULT_PAYLOAD_LIST)
            engine.queue(target.req, req)


# ========== PITCHFORK ==========
def _attack_pitchfork(engine, target, payload_sets, mode):
    for payload_tuple in zip(*payload_sets):
        transformed_sets = []

        for payload in payload_tuple:
            transformed_list = transformed_payloads(payload, mode)
            if not transformed_list:
                break
            transformed_sets.append(transformed_list)
        else:
            for transformed in zip(*transformed_sets):
                if any(is_excluded_payload(item) for item in transformed):
                    continue
                engine.queue(target.req, [encode_for_request(item) for item in transformed])


# ========== CLUSTER BOMB ==========
def _attack_cluster_bomb(engine, target, payload_sets, mode):
    for combo in itertools.product(*payload_sets):
        transformed_sets = []

        for payload in combo:
            transformed_list = transformed_payloads(payload, mode)
            if not transformed_list:
                break
            transformed_sets.append(transformed_list)
        else:
            for transformed in itertools.product(*transformed_sets):
                if any(is_excluded_payload(item) for item in transformed):
                    continue
                engine.queue(target.req, [encode_for_request(item) for item in transformed])


ATTACK_HANDLERS = {
    'default': _attack_default,
    'sniper': _attack_sniper,
    'battering_ram': _attack_battering_ram,
    'pitchfork': _attack_pitchfork,
    'cluster_bomb': _attack_cluster_bomb,
}


def build_payloads(engine, target, wordlists, mode, attack_mode):
    payload_sets = load_payload_sets()
    attack_handler = ATTACK_HANDLERS.get(attack_mode, _attack_default)
    attack_handler(engine, target, payload_sets, mode)


RECURSIVE_WORDS = []
if RECURSIVE:
    RECURSIVE_WORDS = load_payload_sets()[0]


def recursive_requests(req, mode, base):
    for word in RECURSIVE_WORDS:
        for transformed in transformed_payloads(word, mode):
            req.engine.queue(req.template, base + transformed)


def queueRequests(target, wordlists, mode=MODE1, attack_mode=ATTACK_MODE):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=ENGINE_CONFIG['concurrentConnections'],
        requestsPerConnection=ENGINE_CONFIG['requestsPerConnection'],
        pipeline=ENGINE_CONFIG['pipeline']
    )

    build_payloads(
        engine=engine,
        target=target,
        wordlists=wordlists,
        mode=mode,
        attack_mode=attack_mode
    )


def handleResponse(req, interesting, mode=MODE1):
    if not req.status:
        return

    passed = evaluate_request(
        req.status,
        req.wordcount,
        req.length,
        req.response
    )

    if passed:
        table.add(req)

    if FOLLOW_REDIRECT and 300 <= req.status < 400:
        match = re.search(r'(?i)^Location:\s*(.+)$', req.response, re.MULTILINE)
        if match:
            location_header = match.group(1).strip()

            check = True
            for loc in EXCLUDED_LOCATIONS:
                if loc in location_header:
                    check = False
                    break

            if check:
                parsed = urlparse(location_header)
                if parsed.netloc:
                    redirect_path = parsed.path
                else:
                    redirect_path = location_header

                print(location_header)

                if redirect_path.startswith('/'):
                    redirect_path = redirect_path[1:]

                req.engine.queue(req.template, redirect_path)
                return

    recursive_base = None

    if RECURSIVE_TO_ANY_HIT and passed and not req.words[0].endswith('/'):
        recursive_base = req.words[0] + '/'

    if RECURSIVE and passed and req.words[0].endswith('/'):
        recursive_requests(req, mode, req.words[0])

    elif RECURSIVE and recursive_base:
        recursive_requests(req, mode, recursive_base)

    else:
        return
