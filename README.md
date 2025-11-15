### BoberIntruder — Turbo Intruder payload/script for content discovery

#### Overview

BoberIntruder is a Turbo Intruder script intended to extend Burp's high-speed request engine with flexible payload transformation, response evaluation and simple redirect/recursive crawling logic. It is designed for directory and file discovery workflows (wordlist-driven), with hooks to customize how words are transformed before sending, which responses are considered interesting, and how redirects and recursive enumeration are handled.

Turbo Intruder context

- Turbo Intruder is a Burp extension that lets you drive many HTTP requests quickly from custom Python scripts. BoberIntruder is written in that scripting style and plugs into Turbo Intruder’s request engine via the expected queueRequests and handleResponse functions. Use it inside Turbo Intruder when you want more control over payload processing, redirect following and result filtering than a plain wordlist runner provides.

---

#### Key capabilities

- Payload transformation modes
    - url_enc: URL-encodes each word before queuing.
    - extensions: URL-encodes then appends a configurable list of file extensions (e.g., .txt, .php, or empty) to each word.
    - base64: encodes word with base64.
    - any: user-defined transformation function (example provided that appends a trailing slash).
    - none: pass-through (no transformation).
- Wordlist-driven request queuing
    - Reads a wordlist file once, removes empty lines, transforms each entry and queues requests concurrently.
- Response evaluation and filtering
    - evaluate_request lets you define simple predicate rules (status, wordcount, length, response content) to skip or accept responses. Configurable via a small list of lambda predicates.
- Redirect handling
    - Optional automatic follow of Location headers for 3xx responses; extracts path portion from absolute redirects and queues it for further requests.
    - Excludes configured redirect locations to avoid loops or undesired destinations.
- Recursive enumeration
    - Optional recursive mode that, when a successful path ends with a trailing slash, will append entries from a second wordlist to the path and queue those requests.
- Exclusions and loop prevention
    - EXCLUDED_ENDPOINTS prevents queuing known endpoints (e.g., logout).
    - EXCLUDED_LOCATIONS prevents following specific redirect targets.
- Safe-fail behavior
    - If a rule predicate raises an exception while evaluating a response, the script treats that response as skipped to avoid breaking the run.

---

#### Configuration (top of script)

- Payload transformer selection
    - MODE1: mode used when queuing initial requests (default 'url_enc').
    - MODE2: mode used during handleResponse recursive/queued follow-up requests (default 'url_enc').
- Wordlists
    - LIST1: primary wordlist used by queueRequests (default: /usr/share/seclists/Discovery/Web-Content/common.txt).
    - LIST2: secondary wordlist used for recursive enumeration (default: same as LIST1).
- Concurrency (in queueRequests)
    - concurrentConnections=5, requestsPerConnection=100, pipeline=False (adjust inside queueRequests if needed).
- Redirect / recursion toggles
    - FOLLOW_REDIRECT (True/False)
    - RECURSIVE (True/False)
- Exclusions
    - EXCLUDED_ENDPOINTS: list of endpoint names to never queue (e.g., ['logout']).
    - EXCLUDED_LOCATIONS: list of substrings to detect in Location headers to avoid following.

---

#### How it works (high level)

- queueRequests(target, wordlists, mode)
    - Instantiates Turbo Intruder’s RequestEngine and reads LIST1 once.
    - For each non-empty word from LIST1: transforms the word by the selected mode, filters against EXCLUDED_ENDPOINTS, and enqueues the request template with the transformed word.
- handleResponse(req, interesting, mode)
    - Called for each response. Uses evaluate_request to decide if the response should be added to the results table.
    - If FOLLOW_REDIRECT is enabled and status is 3xx, the script attempts to extract a Location header from the response body with a case-insensitive regex, filters it against EXCLUDED_LOCATIONS, normalizes absolute URLs to a path, strips a leading slash, and queues a new request for that path.
    - If RECURSIVE is enabled and the originating word ends with '/', the script reads LIST2, transforms each entry, filters exclusions and queues additional requests under the current path.

---

#### Customize quickly

- Add or-change transformation behaviors
    - Edit transformer() to add new modes or change existing behavior. Implement complex encodings or templating logic inside encode_base64() or the any() function.
- Fine-tune response filtering
    - Edit RULES inside evaluate_request with predicates to skip uninteresting responses (status codes, exact lengths, presence/absence of strings, wordcount heuristics).
- Prevent loops and noisy targets
    - Populate EXCLUDED_ENDPOINTS and EXCLUDED_LOCATIONS to stop hitting logout endpoints or redirect loops.
- Adjust concurrency
    - Change RequestEngine parameters in queueRequests to match your lab limits and the target tolerance.

---

#### Practical notes and caveats

- Turbo Intruder environment
    - This script expects to run inside Turbo Intruder and uses RequestEngine, req.template, req.engine.queue, table.add and other Turbo Intruder globals. It is not a standalone Python crawler.
- Location header extraction
    - The script parses Location from the raw response text using a regex; if the extension or target returns headers differently, consider using a different extraction method if Turbo Intruder exposes parsed headers.
- URL normalization
    - For absolute redirects, the script uses urlparse and only keeps the path portion. Leading slashes are stripped to form relative queue values; adapt this if your target requires a different normalization (e.g., keep leading slash or include query).
- Error handling
    - Predicates that raise exceptions cause the response to be skipped. This conservative behavior prevents a single bad predicate from stopping the run, but ensure your predicates are robust to avoid false skips.
- Wordlist files
    - Ensure LIST1 and LIST2 paths are correct and readable by your Burp/Turbo Intruder process.

---

#### Example quick edits

- Add .bak to extensions: update get_extensions() to include '.bak'.
- Treat 404 as reject: uncomment or add lambda s, w, l, r: s == 404 inside RULES.
- Non-URL-encoded queuing: set MODE1 = 'none' to send raw words.

---
