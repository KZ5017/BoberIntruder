```python
import base64
import urllib
from urlparse import urlparse
import re
import itertools

# ------------------------------- PAYLOAD TRANSFORMER CODE SECTION ------------------------------- #

# -------- FILE EXTENSION SELECTION(U CAN EXPAND IT ) --------#
def get_extensions():
    return ['.txt', '']

# -------- FULL CUSTOM CODE FOR TRANSFORMATION --------#
def custom(word):
    combined = 'http://' + word + '/etc/passwd'
    encoded = base64.b64encode(combined)
    
    return [encoded]

def encode_base64(word):
    # Some code here if need it.
    encoded_string = base64.b64encode(word.encode('utf-8')).decode('utf-8')
    return [encoded_string]

def transformer(word, mode='url_enc'):
    if mode == 'url_enc':
        word = urllib.quote(word)
        return [word]
        
    elif mode == 'extensions':
        word = urllib.quote(word)
        extensions = get_extensions()
        return [word + ext for ext in extensions]
        
    elif mode == 'base64':
        return encode_base64(word)
        
    elif mode == 'custom':
        word = urllib.quote(word)
        return custom(word)
        
    else:
        return [word]

# ------------------------------- RESPONSE EVALUATION CODE SECTION ------------------------------- #

def evaluate_request(status, wordcount, length, response):
    """
    Return: True (accept) or None (skip)

    RULES contains simple callables (predicates).
    If any predicate matches, the request is skipped (return None).
    Edit this list to enable/disable rules instead of commenting blocks.
    """

    # RULES: edit these lines to enable/disable checks
    RULES = [
        #lambda s, w, l, r: w < 2225,               # skip when wordcount equals 115
        #lambda s, w, l, r: w == 152,               # skip when wordcount equals 150
        #lambda s, w, l, r: s == 404,               # skip when status is 404
        #lambda s, w, l, r: s == 200,               # skip when status is 404
        lambda s, w, l, r: l == 389,               # skip when length equals 363
        #lambda s, w, l, r: l == 7410,               # skip when length equals 363
        #lambda s, w, l, r: "index.php?err=Invalid Username" in r,  # skip when response 'contains' OR  use "not in" to 'not contains' exact substring
    ]

    for pred in RULES:
        try:
            if pred(status, wordcount, length, response):
                return None
        except Exception:
            # If a rule raises, treat it as a skip to avoid breaking the caller.
            return None

    return True

# ------------------------------- PAYLOADS OR LOCATIONS EXCLUSION SECTION ------------------------------- #

# use this list to prevent calling endpoints like "logout.php"
EXCLUDED_PAYLOADS = ['logout']
# use this list to prevent a loop because of REDIRECTION(301/302) to same location
EXCLUDED_LOCATIONS = ['LocationListWhereTheApplication','EveryTimeRedirectingUs.html']
# Redirection following

# ------------------------------- RECURSIVE MODE SELECT SECTION ------------------------------- #

FOLLOW_REDIRECT = True
# Resursive mode
RECURSIVE = False
# recursive to any hit
RECURSIVE_TO_ANY_HIT = False

# ------------------------------- PAYLOAD TRANSFORMER MODE SELECT SECTION ------------------------------- #

#IN THIS LINE YOU CAN CHANGE THE PROCESSING MODE: MODE* ='url_enc', 'extensions'(U CAN EXPAND IT ), 'base64, 'custom'(FULL CUSTOM CODE) or 'none' to no transform.
MODE1 = 'url_enc'
#MODE2 = 'url_enc'

# ------------------------------- WORDLIST SELECT SECTION ------------------------------- #

#WORDLIST like r'/usr/share/seclists/Discovery/Web-Content/common.txt'
PAYLOAD_LISTS = [
    #LIST1
    r'/usr/share/seclists/Discovery/Web-Content/common.txt',
    #LIST2
    r'/usr/share/seclists/Discovery/Web-Content/common.txt',
    #LIST3
    #r'/usr/share/seclists/Discovery/Web-Content/common.txt'
]


DEFAULT_PAYLOAD_LIST = [
    'payload1',
    'payload2',
    #'payload3',
]

# ------------------------------- ATTACK MODE SELECT SECTION ------------------------------- #
ATTACK_MODE = 'default'
# default : single payloadmarker, using wordlist: LIST1
# sniper : multiple payloadmarker, testing one by one target, using wordlist: LIST1
# battering_ram : multiple payloadmarker, testing same payload into all positions simultaneously, using wordlist: LIST1
# pitchfork : multiple payloadmarker, testing payloads in parallel (1st payload set → 1st position, etc.)
# cluster_bomb : multiple payloadmarker, testing every combination of payloads

# ------------------------------- ATTACK MODE CODE LOGIC SECTION ------------------------------- #

# ========== DEFAULT ==========
def _attack_default(engine, target, payload_sets, mode):
    for payload in payload_sets[0]:
        for t in transformer(payload, mode):
            if t in EXCLUDED_PAYLOADS:
                continue
            engine.queue(target.req, t)

# ========== SNIPER ==========
def _attack_sniper(engine, target, payload_sets, mode):
    for index in range(len(DEFAULT_PAYLOAD_LIST)):
        for payload in payload_sets[0]:
            for t in transformer(payload, mode):
                if t in EXCLUDED_PAYLOADS:
                    continue

                req = DEFAULT_PAYLOAD_LIST[:]
                req[index] = urllib.quote(t)

                engine.queue(target.req, req)

# ========== BATTERING RAM ==========
def _attack_battering_ram(engine, target, payload_sets, mode):
    for payload in payload_sets[0]:
        for t in transformer(payload, mode):
            if t in EXCLUDED_PAYLOADS:
                continue

            encoded = urllib.quote(t)

            req = [encoded] * len(DEFAULT_PAYLOAD_LIST)

            engine.queue(target.req, req)

# ========== PITCHFORK ==========
def _attack_pitchfork(engine, target, payload_sets, mode):
    for payload_tuple in zip(*payload_sets):

        transformed_sets = []

        for payload in payload_tuple:
            transformed_list = list(transformer(payload, mode))
            if not transformed_list:
                break
            transformed_sets.append(transformed_list)
        else:
            for transformed in zip(*transformed_sets):
                if any(p in EXCLUDED_PAYLOADS for p in transformed):
                    continue
                engine.queue(
                    target.req,
                    [urllib.quote(p) for p in transformed]
                )

# ========== CLUSTER BOMB ==========
def _attack_cluster_bomb(engine, target, payload_sets, mode):
    for combo in itertools.product(*payload_sets):

        transformed_sets = []

        for payload in combo:
            transformed_list = list(transformer(payload, mode))
            if not transformed_list:
                break
            transformed_sets.append(transformed_list)
        else:
            for transformed in itertools.product(*transformed_sets):
                if any(p in EXCLUDED_PAYLOADS for p in transformed):
                    continue

                engine.queue(
                    target.req,
                    [urllib.quote(p) for p in transformed]
                )


def build_payloads(engine, target, wordlists, mode, attack_mode):

    # --- LOADING WORDLISTS ---
    payload_sets = []
    for path in PAYLOAD_LISTS:
        with open(path) as f:
            payload_sets.append(
                [line.rstrip() for line in f if line.strip()]
            )

    # --- ATTACK MODE DISPATCH ---
    if attack_mode == 'default':
        _attack_default(engine, target, payload_sets, mode)

    elif attack_mode == 'sniper':
        _attack_sniper(engine, target, payload_sets, mode)

    elif attack_mode == 'battering_ram':
        _attack_battering_ram(engine, target, payload_sets, mode)

    elif attack_mode == 'pitchfork':
        _attack_pitchfork(engine, target, payload_sets, mode)

    elif attack_mode == 'cluster_bomb':
        _attack_cluster_bomb(engine, target, payload_sets, mode)


# ------------------------------- SOME CODE FOR RECURSIVE ------------------------------- #

if RECURSIVE:
    with open(PAYLOAD_LISTS[0]) as f:
        RECURSIVE_WORDS = [line.rstrip() for line in f if line.strip()]

def recursive_requests(req, mode, base):
    for word in RECURSIVE_WORDS:
        for t in transformer(word, mode):
            if t not in EXCLUDED_PAYLOADS:
                req.engine.queue(req.template, base + t)

# ------------------------------- CORE CODE LOGIC SECTION ------------------------------- #

def queueRequests(target, wordlists, mode = MODE1, attack_mode=ATTACK_MODE):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=3,
                           requestsPerConnection=100,
                           pipeline=False)

    build_payloads(
        engine=engine,
        target=target,
        wordlists=wordlists,
        mode=mode,
        attack_mode=attack_mode
    )


def handleResponse(req, interesting, mode = MODE1):
    # currently available attributes are req.status, req.wordcount, req.length and req.response
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
        # We try to extract the Location header from the response text
        match = re.search(r'(?i)^Location:\s*(.+)$', req.response, re.MULTILINE)
        if match:
            location_header = match.group(1).strip()

            # Check for excluded purposes
            check = True
            for loc in EXCLUDED_LOCATIONS:
                if loc in location_header:
                    check = False
                    break

            if check:
                # If it's an absolute URL, only the path part is used
                parsed = urlparse(location_header)
                if parsed.netloc:
                    redirect_path = parsed.path
                else:
                    redirect_path = location_header

                print(location_header)

                # If the path starts with '/', remove the first slash
                if redirect_path.startswith('/'):
                    redirect_path = redirect_path[1:]
                
                # New request for redirect
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

```
