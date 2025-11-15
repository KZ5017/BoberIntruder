```python
import base64
import urllib
from urlparse import urlparse
import re

# ------------------------------- PAYLOAD TRANSFORMER SRCTION ------------------------------- #

# -------- FILE EXTENSION SELECTION(U CAN EXPAND IT ) --------#
def get_extensions():
    return ['.txt', '.php', '']

# -------- FULL CUSTOM CODE FOR TRANSFORMATION --------#
def any(word):
    # example: we got code 301 response after every request, so we cant check "http://domain.name/word/" automatically,
    # but we can add "/" manually after every word.
    result = word + "/"
    #result = word
    return [result]

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
        
    elif mode == 'any':
        word = urllib.quote(word)
        return any(word)
        
    else:
        return [word]

# ------------------------------- RESPONSE EVALUATION SECTION ------------------------------- #

def evaluate_request(status, wordcount, length, response):
    """
    Return: True (accept) or None (skip)

    RULES contains simple callables (predicates).
    If any predicate matches, the request is skipped (return None).
    Edit this list to enable/disable rules instead of commenting blocks.
    """

    # RULES: edit these lines to enable/disable checks
    RULES = [
        lambda s, w, l, r: w == 115,               # skip when wordcount equals 115
        lambda s, w, l, r: w == 150,               # skip when wordcount equals 150
        #lambda s, w, l, r: s == 404,               # skip when status is 404
        #lambda s, w, l, r: l == 363,               # skip when length equals 363
        #lambda s, w, l, r: "User not found" in r,  # skip when response 'contains' OR  use "not in" to 'not contains' exact substring
    ]

    for pred in RULES:
        try:
            if pred(status, wordcount, length, response):
                return None
        except Exception:
            # If a rule raises, treat it as a skip to avoid breaking the caller.
            return None

    return True

# ------------------------------- ENDPOINT EXCLUSION SECTION ------------------------------- #

# use this list to prevent calling endpoints like "logout.php"
EXCLUDED_ENDPOINTS = ['logout']
# use this list to prevent a loop because of REDIRECTION(301/302) to same location
EXCLUDED_LOCATIONS = ['LocationListWhereTheApplication','EveryTimeRedirectingUs.html']
# Redirection following

# ------------------------------- RECURSIVE MODE SELECT SECTION ------------------------------- #

FOLLOW_REDIRECT = True
# Resursive mode
RECURSIVE = True

# ------------------------------- PAYLOAD TRANSFORMER MODE SELECT SECTION ------------------------------- #

#IN THIS LINE YOU CAN CHANGE THE PROCESSING MODE: MODE* ='url_enc', 'extensions'(U CAN EXPAND IT ), 'base64, 'any'(FULL CUSTOM CODE) or 'none' to no transform.
MODE1 = 'url_enc'
MODE2 = 'url_enc'

# ------------------------------- WORDLIST SELECT SECTION ------------------------------- #

#WORDLIST like r'/usr/share/seclists/Discovery/Web-Content/common.txt'
LIST1 = r'/usr/share/seclists/Discovery/Web-Content/common.txt'
LIST2 = r'/usr/share/seclists/Discovery/Web-Content/common.txt'

# ------------------------------- CODE LOGIC SECTION ------------------------------- #

def queueRequests(target, wordlists, mode = MODE1):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=100,
                           pipeline=False)
    
    # Read the wordlist once and filter out empty lines
    with open(LIST1) as f:
        words = [line.rstrip() for line in f if line.strip()]  # Remove empty lines
    
    for word in words:
        transformed_words = transformer(word, mode)
        for transformed_word in transformed_words:
            if transformed_word not in EXCLUDED_ENDPOINTS:
                engine.queue(target.req, transformed_word)


def handleResponse(req, interesting, mode = MODE2):
    # currently available attributes are req.status, req.wordcount, req.length and req.response
    if req.status:
        if evaluate_request(req.status, req.wordcount, req.length, req.response):       
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

        if RECURSIVE and evaluate_request(req.status, req.wordcount, req.length, req.response) and req.words[0].endswith('/'):
            with open(LIST2) as f:
                words = [line.rstrip() for line in f if line.strip()]
            for word in words:
                transformed_words = transformer(word, mode)
                for transformed_word in transformed_words:
                    if transformed_word not in EXCLUDED_ENDPOINTS:
                        req.engine.queue(req.template, req.words[0] + transformed_word)
                        
```
