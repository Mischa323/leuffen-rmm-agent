"""Dependency-free SNMP v1 / v2c client (node capability).

A small, self-contained SNMP manager used by a node to poll configured targets
over UDP/161. No third-party libraries: it speaks just enough BER/ASN.1 to do
GET (one or many scalar OIDs in a single PDU) and GETNEXT-based walks, for
SNMP v1 (version 0) and v2c (version 1). SNMPv3 is intentionally out of scope
for now — it needs USM auth/priv that really wants a crypto library.

Public API:
    get(host, community, oids, version="2c", port=161, timeout=2.0, retries=1)
        -> {"ok": bool, "error": str|None, "varbinds": [(oid, value, type_name)]}
    walk(host, community, base_oid, version="2c", ...) -> list[(oid, value, type)]

Values are decoded to Python types: ints for INTEGER/Counter/Gauge/TimeTicks/
Counter64, str for OCTET STRING (utf-8, else hex), dotted str for OID/IpAddress,
None for NULL, and the strings "noSuchObject"/"noSuchInstance"/"endOfMibView"
for the v2c exception markers.
"""
from __future__ import annotations

import random
import socket

# --- ASN.1 / BER tags -------------------------------------------------------
T_INT = 0x02
T_OCTET = 0x04
T_NULL = 0x05
T_OID = 0x06
T_SEQ = 0x30
# SNMP application types
T_IPADDR = 0x40
T_COUNTER32 = 0x41
T_GAUGE32 = 0x42
T_TIMETICKS = 0x43
T_OPAQUE = 0x44
T_COUNTER64 = 0x46
# PDU types (context-specific, constructed)
PDU_GET = 0xA0
PDU_GETNEXT = 0xA1
PDU_RESPONSE = 0xA2
PDU_GETBULK = 0xA5
# v2c varbind exception markers (context-specific, primitive)
EXC_NOSUCHOBJECT = 0x80
EXC_NOSUCHINSTANCE = 0x81
EXC_ENDOFMIBVIEW = 0x82

_EXC = {EXC_NOSUCHOBJECT: "noSuchObject", EXC_NOSUCHINSTANCE: "noSuchInstance",
        EXC_ENDOFMIBVIEW: "endOfMibView"}
_TYPE_NAME = {
    T_INT: "INTEGER", T_OCTET: "STRING", T_NULL: "NULL", T_OID: "OID",
    T_IPADDR: "IpAddress", T_COUNTER32: "Counter32", T_GAUGE32: "Gauge32",
    T_TIMETICKS: "TimeTicks", T_OPAQUE: "Opaque", T_COUNTER64: "Counter64",
    EXC_NOSUCHOBJECT: "noSuchObject", EXC_NOSUCHINSTANCE: "noSuchInstance",
    EXC_ENDOFMIBVIEW: "endOfMibView",
}
# v1 error-status codes (a subset; v2c adds many more we surface numerically).
_ERR = {0: None, 1: "tooBig", 2: "noSuchName", 3: "badValue", 4: "readOnly",
        5: "genErr"}


# --- BER encoding -----------------------------------------------------------
def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(value)) + value


def _enc_int(n: int) -> bytes:
    length = (n.bit_length() + 8) // 8 or 1
    return _tlv(T_INT, n.to_bytes(length, "big", signed=True))


def _b128(n: int) -> bytes:
    """Base-128, high bit set on all but the last byte (OID subidentifier)."""
    if n == 0:
        return b"\x00"
    chunks = []
    while n:
        chunks.insert(0, n & 0x7F)
        n >>= 7
    for i in range(len(chunks) - 1):
        chunks[i] |= 0x80
    return bytes(chunks)


def _enc_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.strip().strip(".").split(".") if x != ""]
    if len(parts) < 2:
        raise ValueError(f"OID too short: {oid!r}")
    body = _b128(40 * parts[0] + parts[1])
    for p in parts[2:]:
        body += _b128(p)
    return _tlv(T_OID, body)


def _varbind(oid: str) -> bytes:
    return _tlv(T_SEQ, _enc_oid(oid) + _tlv(T_NULL, b""))


def _build_message(version: int, community: str, pdu: bytes) -> bytes:
    return _tlv(T_SEQ, _enc_int(version) + _tlv(T_OCTET, community.encode()) + pdu)


def _build_pdu(pdu_type: int, request_id: int, varbinds: list[bytes],
               a: int = 0, b: int = 0) -> bytes:
    # For GET/GETNEXT a/b are error-status/error-index (0); for GETBULK they are
    # non-repeaters / max-repetitions.
    body = _enc_int(request_id) + _enc_int(a) + _enc_int(b) + _tlv(T_SEQ, b"".join(varbinds))
    return _tlv(pdu_type, body)


# --- BER decoding -----------------------------------------------------------
def _parse_tlv(data: bytes, idx: int):
    """Return (tag, value_bytes, next_idx)."""
    tag = data[idx]
    idx += 1
    length = data[idx]
    idx += 1
    if length & 0x80:
        nb = length & 0x7F
        length = int.from_bytes(data[idx:idx + nb], "big")
        idx += nb
    value = data[idx:idx + length]
    return tag, value, idx + length


def _decode_oid(value: bytes) -> str:
    if not value:
        return ""
    # Decode every subidentifier as base-128 first; the first one then splits
    # into the leading two arcs (X*40 + Y), and may itself be multi-byte.
    subs = []
    n = 0
    for byte in value:
        n = (n << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            subs.append(n)
            n = 0
    first = subs[0]
    if first < 40:
        head = [0, first]
    elif first < 80:
        head = [1, first - 40]
    else:
        head = [2, first - 80]
    return ".".join(str(p) for p in head + subs[1:])


def _decode_value(tag: int, value: bytes):
    if tag == T_INT:
        return int.from_bytes(value, "big", signed=True)
    if tag in (T_COUNTER32, T_GAUGE32, T_TIMETICKS, T_COUNTER64):
        return int.from_bytes(value, "big", signed=False)
    if tag == T_OCTET or tag == T_OPAQUE:
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError:
            return value.hex()
    if tag == T_OID:
        return _decode_oid(value)
    if tag == T_IPADDR:
        return ".".join(str(b) for b in value)
    if tag == T_NULL:
        return None
    if tag in _EXC:
        return _EXC[tag]
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.hex()


def _parse_response(data: bytes) -> dict:
    _, msg, _ = _parse_tlv(data, 0)            # outer SEQUENCE
    idx = 0
    _, _ver, idx = _parse_tlv(msg, idx)        # version
    _, _comm, idx = _parse_tlv(msg, idx)       # community
    _pdu_tag, pdu, _ = _parse_tlv(msg, idx)    # PDU
    pidx = 0
    _, rid, pidx = _parse_tlv(pdu, pidx)
    _, errst, pidx = _parse_tlv(pdu, pidx)
    _, errix, pidx = _parse_tlv(pdu, pidx)
    _, vblist, pidx = _parse_tlv(pdu, pidx)
    varbinds = []
    vidx = 0
    while vidx < len(vblist):
        _, vb, vidx = _parse_tlv(vblist, vidx)
        bidx = 0
        _, oid_v, bidx = _parse_tlv(vb, bidx)
        vtag, val_v, bidx = _parse_tlv(vb, bidx)
        varbinds.append((_decode_oid(oid_v), _decode_value(vtag, val_v),
                         _TYPE_NAME.get(vtag, f"tag{vtag:#x}")))
    return {
        "request_id": int.from_bytes(rid, "big", signed=True),
        "error_status": int.from_bytes(errst, "big", signed=True),
        "error_index": int.from_bytes(errix, "big", signed=True),
        "varbinds": varbinds,
    }


# --- transport --------------------------------------------------------------
def _version_num(version) -> int:
    return 0 if str(version).lstrip("v") in ("1",) else 1


def _udp_query(host: str, port: int, msg: bytes, timeout: float, retries: int):
    last = None
    for _ in range(max(retries, 0) + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(msg, (host, port))
                data, _addr = s.recvfrom(65535)
                return data, None
        except socket.timeout:
            last = "timeout"
        except OSError as exc:
            last = str(exc)
    return None, last


# --- public API -------------------------------------------------------------
def get(host: str, community: str, oids, version="2c", port: int = 161,
        timeout: float = 2.0, retries: int = 1) -> dict:
    """GET one or more scalar OIDs in a single request."""
    if isinstance(oids, str):
        oids = [oids]
    oids = [o for o in oids if o]
    if not oids:
        return {"ok": False, "error": "no OIDs", "varbinds": []}
    ver = _version_num(version)
    rid = random.randint(1, 0x7FFFFFFF)
    try:
        pdu = _build_pdu(PDU_GET, rid, [_varbind(o) for o in oids])
    except ValueError as exc:
        return {"ok": False, "error": str(exc), "varbinds": []}
    data, err = _udp_query(host, port, _build_message(ver, community, pdu), timeout, retries)
    if data is None:
        return {"ok": False, "error": err or "no response", "varbinds": []}
    try:
        resp = _parse_response(data)
    except (IndexError, ValueError) as exc:
        return {"ok": False, "error": f"decode failed: {exc}", "varbinds": []}
    if resp["error_status"]:
        name = _ERR.get(resp["error_status"], f"error {resp['error_status']}")
        return {"ok": False, "error": name, "varbinds": resp["varbinds"]}
    return {"ok": True, "error": None, "varbinds": resp["varbinds"]}


def _oid_tuple(oid: str):
    return tuple(int(x) for x in oid.split(".") if x != "")


def _in_subtree(oid: str, base: str) -> bool:
    o, b = _oid_tuple(oid), _oid_tuple(base)
    return o[:len(b)] == b and len(o) >= len(b)


def walk(host: str, community: str, base_oid: str, version="2c", port: int = 161,
         timeout: float = 2.0, retries: int = 1, max_rows: int = 512) -> list:
    """GETNEXT walk of a subtree; returns [(oid, value, type_name)]."""
    ver = _version_num(version)
    out: list = []
    cur = base_oid
    for _ in range(max_rows):
        rid = random.randint(1, 0x7FFFFFFF)
        try:
            pdu = _build_pdu(PDU_GETNEXT, rid, [_varbind(cur)])
        except ValueError:
            break
        data, _err = _udp_query(host, port, _build_message(ver, community, pdu), timeout, retries)
        if data is None:
            break
        try:
            resp = _parse_response(data)
        except (IndexError, ValueError):
            break
        if resp["error_status"] or not resp["varbinds"]:
            break
        oid, value, tname = resp["varbinds"][0]
        if tname == "endOfMibView" or not _in_subtree(oid, base_oid):
            break
        out.append((oid, value, tname))
        cur = oid
    return out
