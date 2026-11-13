# SPDX-License-Identifier: AGPL-3.0-or-later
"""Traffic fingerprinting (light deep packet inspection). Pure Python; the standard library only, plus the
optional `cryptography` package for reading QUIC Initial packets.

Reads a pcap (Ethernet or Linux cooked, headers plus the first bytes of each packet), groups packets
into flows and identifies each flow two ways:
  1. signatures in the first payload bytes (TLS ClientHello with SNI, ALPN and ECH; QUIC; DTLS;
     STUN; WireGuard; Tailscale disco; OpenVPN; IKE and ESP; SSH; HTTP; DNS; NTP; BitTorrent),
  2. behaviour from sizes and timing (real-time media, interactive, streaming, bulk, keep-alive,
     tunnel-like), with jitter measured as the spread of the gaps between packets.
Only metadata and signature facts leave this module: never payload bytes.

Input: the pcap bytes that the router gate's "capture" and "ispview" subcommands return.
Settings: EXTRA_DNS_PORTS, a set of extra UDP ports that carry plain DNS (for example a resolver the router
runs on a non-standard port). The collector may fill it from config.json. Touches nothing outside this module.
"""
import hashlib
import hmac
import ipaddress
import math
import re
import statistics
import struct

EXTRA_DNS_PORTS = set()

PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fe80::/10", "fc00::/7")]


def is_local(ip):
    """True for private, carrier-grade NAT, link-local and unique-local addresses."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in PRIVATE)


# ------------------------------------------------------------------ pcap
def packets(data, with_ttl=False):
    """Yield (ts, src, dst, proto, sport, dport, ip_len, payload, tcp_flags, payload_len[, ttl]) from a pcap byte string."""
    if len(data) < 24:
        return
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
    else:
        return
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    link = struct.unpack(e + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack(e + "IIII", data[off:off + 16])
        off += 16
        frame = data[off:off + incl]
        off += incl
        ts = sec + frac / (1e9 if nano else 1e6)
        if link == 1:                      # Ethernet (skip VLAN tags)
            if len(frame) < 14:
                continue
            et, p = struct.unpack("!H", frame[12:14])[0], 14
            while et in (0x8100, 0x88A8) and len(frame) >= p + 4:
                et, p = struct.unpack("!H", frame[p + 2:p + 4])[0], p + 4
        elif link == 113:                  # Linux cooked capture
            if len(frame) < 16:
                continue
            et, p = struct.unpack("!H", frame[14:16])[0], 16
        else:
            continue
        ip = frame[p:]
        if et == 0x0800 and len(ip) >= 20:
            ihl = (ip[0] & 15) * 4
            tot = struct.unpack("!H", ip[2:4])[0]
            proto = ip[9]
            ttl = ip[8]
            src, dst = socket_ntoa(ip[12:16]), socket_ntoa(ip[16:20])
            l4 = ip[ihl:]
        elif et == 0x86DD and len(ip) >= 40:
            tot = struct.unpack("!H", ip[4:6])[0] + 40
            proto = ip[6]
            ttl = ip[7]
            src, dst = str(ipaddress.IPv6Address(ip[8:24])), str(ipaddress.IPv6Address(ip[24:40]))
            l4 = ip[40:]
        else:
            continue
        sport = dport = 0
        flags = 0
        payload = b""
        if proto == 6 and len(l4) >= 20:
            sport, dport = struct.unpack("!HH", l4[:4])
            doff = (l4[12] >> 4) * 4
            flags = l4[13]
            payload = l4[doff:]
            plen = max(0, tot - (len(ip) - len(l4)) - doff) if et == 0x0800 else len(payload)
        elif proto == 17 and len(l4) >= 8:
            sport, dport, ulen = struct.unpack("!HHH", l4[:6])
            payload = l4[8:]
            plen = max(0, ulen - 8)
        else:
            plen = 0
        row = (ts, src, dst, {6: "tcp", 17: "udp", 50: "esp", 1: "icmp", 58: "icmp6"}.get(proto, str(proto)), sport, dport, tot, payload, flags, plen)
        yield row + (ttl,) if with_ttl else row


def socket_ntoa(b):
    """Dotted IPv4 text from four bytes."""
    return ".".join(str(x) for x in b)


# ------------------------------------------------------------------ signatures
QUIC_VERSIONS = {0x00000001: "QUIC v1", 0x6B3343CF: "QUIC v2", 0xFF00001D: "QUIC draft-29", 0x00000000: "QUIC version negotiation"}
TOR_SNI = re.compile(r"^www\.[a-z0-9]{8,20}\.(com|net)$")


def tls_client_hello(p):
    """Parse a TLS ClientHello from the start of a TCP payload. Returns dict or None."""
    if len(p) < 11 or p[0] != 0x16 or p[1] != 0x03 or p[5] != 0x01:
        return None
    out = {"sni": None, "alpn": [], "ech": False, "versions": [], "groups": [], "ciphers": 0, "exts": 0}
    try:
        i = 9 + 2 + 32                               # record(5) + hs header(4) + version(2) + random(32)
        sid = p[i]; i += 1 + sid
        cl = struct.unpack("!H", p[i:i + 2])[0]; out["ciphers"] = cl // 2; i += 2 + cl
        comp = p[i]; i += 1 + comp
        el = struct.unpack("!H", p[i:i + 2])[0]; i += 2
        end = min(len(p), i + el)
        while i + 4 <= end:
            t, ln = struct.unpack("!HH", p[i:i + 4]); i += 4
            body = p[i:i + ln]; i += ln
            out["exts"] += 1
            if t == 0 and len(body) > 5:
                n = struct.unpack("!H", body[3:5])[0]
                out["sni"] = body[5:5 + n].decode("ascii", "replace")
            elif t == 16 and len(body) > 2:
                j = 2
                while j < len(body):
                    n = body[j]; out["alpn"].append(body[j + 1:j + 1 + n].decode("ascii", "replace")); j += 1 + n
            elif t == 0xFE0D:
                out["ech"] = True
            elif t == 43 and body:
                out["versions"] = [struct.unpack("!H", body[k:k + 2])[0] for k in range(1, 1 + body[0], 2) if k + 2 <= len(body)]
            elif t == 51 and len(body) > 2:
                j = 2
                while j + 4 <= len(body):
                    g, kl = struct.unpack("!HH", body[j:j + 4]); out["groups"].append(g); j += 4 + kl
    except (IndexError, struct.error):
        pass
    out["pq"] = any(g in (0x11EC, 0x6399, 0x11EB, 0x11ED) for g in out["groups"])    # hybrid post-quantum key exchange (ML-KEM)
    out["tls13"] = 0x0304 in out["versions"]
    return out


def signature(proto, sport, dport, p, plen):
    """Identify a protocol from the first payload of a flow. Returns (label, evidence) or (None, None)."""
    if not p:
        return None, None
    ports = {sport, dport}
    if proto == "tcp":
        ch = tls_client_hello(p)
        if ch:
            bits = [f"SNI {ch['sni']}" if ch["sni"] else "no SNI"]
            if ch["alpn"]:
                bits.append("ALPN " + ",".join(ch["alpn"][:3]))
            if ch["ech"]:
                bits.append("Encrypted Client Hello")
            if ch["tls13"]:
                bits.append("TLS 1.3")
            if ch["pq"]:
                bits.append("post-quantum key exchange")
            return "TLS", {"text": " · ".join(bits), **ch}
        if p[:1] in (b"\x16", b"\x17", b"\x15", b"\x14") and p[1:2] == b"\x03":
            return "TLS", {"text": "TLS record (session already running)"}
        if p.startswith(b"SSH-"):
            return "SSH", {"text": p.split(b"\r\n")[0][:40].decode("ascii", "replace")}
        m = re.match(rb"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|CONNECT) ", p)
        if m or p.startswith(b"HTTP/1."):
            host = re.search(rb"\r\nHost: ([^\r\n]{1,80})", p)
            return "HTTP (unencrypted)", {"text": (m.group(1).decode() + " " if m else "reply ") + (("to " + host.group(1).decode("ascii", "replace")) if host else "")}
        if p[:20] == b"\x13BitTorrent protocol":
            return "BitTorrent", {"text": "BitTorrent handshake"}
        if len(p) >= 3 and struct.unpack("!H", p[:2])[0] == len(p) - 2 and (p[2] >> 3) in (7, 8, 10):
            return "OpenVPN (TCP)", {"text": f"OpenVPN hard-reset opcode {p[2] >> 3} over TCP"}
        return None, None
    if proto == "udp":
        if len(p) >= 20 and p[4:8] == b"\x21\x12\xa4\x42":
            if 41641 in ports:
                return "STUN", {"text": "STUN from Tailscale (finding its public address)"}
            return "STUN", {"text": "STUN magic cookie 0x2112A442 (call set-up, NAT discovery)"}
        if p.startswith(b"TS\xf0\x9f\x92\xac"):
            return "Tailscale disco", {"text": "Tailscale discovery packet (magic 'TS💬')"}
        if len(p) >= 4 and p[1:4] == b"\x00\x00\x00" and p[0] in (1, 2, 3, 4):
            want = {1: 148, 2: 92, 3: 64}.get(p[0])
            if (want and plen == want) or (p[0] == 4 and plen >= 32 and (plen - 32) % 16 == 0):
                name = {1: "handshake initiation", 2: "handshake response", 3: "cookie reply", 4: "transport data"}[p[0]]
                return "WireGuard", {"text": f"WireGuard {name} (type {p[0]}, {plen} bytes)"}
        if (p[0] & 0xC0) == 0xC0 and len(p) >= 5:
            v = struct.unpack("!I", p[1:5])[0]
            if v in QUIC_VERSIONS:
                return "QUIC", {"text": QUIC_VERSIONS[v] + " long header (HTTP/3 or a QUIC tunnel)"}
        if p[0] in (0x14, 0x15, 0x16, 0x17) and p[1:2] == b"\xfe":
            return "DTLS", {"text": "DTLS record (WebRTC media keys, or a DTLS VPN)"}
        extra = ports & EXTRA_DNS_PORTS
        if (53 in ports or extra) and len(p) >= 12 and p[4:6] == b"\x00\x01":
            return "DNS (unencrypted)", {"text": "plain DNS" + (f" to the router's resolver (port {min(extra)})" if extra else "")}
        if 123 in ports and plen == 48:
            return "NTP", {"text": "time sync"}
        if (500 in ports or 4500 in ports):
            q = p[4:] if (4500 in ports and p[:4] == b"\x00\x00\x00\x00") else p
            if len(q) >= 28 and q[17] == 0x20:
                return "IPsec (IKEv2)", {"text": f"IKEv2 exchange {q[18]}"}
            if 4500 in ports and len(p) >= 8:
                return "IPsec (ESP in UDP)", {"text": "ESP inside UDP 4500"}
        # OpenVPN: opcodes 8, 9 and 10 share their first byte with QUIC short headers, so on 443 only the
        # client hard reset (opcode 7, first byte 0x38) is trusted
        if len(p) >= 14 and (p[0] & 7) == 0 and ((p[0] >> 3) == 7 or ((p[0] >> 3) in (8, 10) and 443 not in ports)):
            return "OpenVPN (UDP)", {"text": f"OpenVPN control opcode {p[0] >> 3}"}
        if (p[0] >> 3) == 9 and plen > 24 and 1194 in ports:
            return "OpenVPN (UDP)", {"text": "OpenVPN P_DATA_V2"}
        if 443 in ports and (p[0] & 0xC0) == 0x40:
            return "QUIC", {"text": "QUIC short header (session already running)"}
        if 5353 in ports or 1900 in ports or 5351 in ports or 137 in ports or 138 in ports:
            return "Local discovery", {"text": "mDNS, SSDP, NAT-PMP or NetBIOS"}
        if p[:2] == b"d1" and b":ad2:id20:" in p[:40]:
            return "BitTorrent DHT", {"text": "BitTorrent DHT"}
    if proto == "esp":
        return "IPsec (ESP)", {"text": "IP protocol 50"}
    return None, None


def entropy(b):
    """Shannon entropy of a byte string, in bits per byte."""
    if not b:
        return 0.0
    c = {}
    for x in b:
        c[x] = c.get(x, 0) + 1
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


# ------------------------------------------------------------------ flows and behaviour
def analyse(data, window=None):
    """Group a pcap into flows and label each one. Returns {"t0", "t1", "flows": [...]}, biggest flow first."""
    flows = {}
    t_first = t_last = None
    for ts, src, dst, proto, sport, dport, tot, payload, flags, plen in packets(data):
        t_first = ts if t_first is None else min(t_first, ts)
        t_last = ts if t_last is None else max(t_last, ts)
        if proto in ("icmp", "icmp6"):
            continue
        ls, ld = is_local(src), is_local(dst)
        if ls and not ld:
            key, up = (src, sport, dst, dport, proto), True
        elif ld and not ls:
            key, up = (dst, dport, src, sport, proto), False
        else:                                       # both local: the side with the higher port is the client
            if (sport, src) >= (dport, dst):
                key, up = (src, sport, dst, dport, proto), True
            else:
                key, up = (dst, dport, src, sport, proto), False
        f = flows.get(key)
        if f is None:
            f = flows[key] = {"pk": [], "sig": None, "ev": None, "first_up": None, "first_dn": None, "hs": 0}
        f["pk"].append((ts, 1 if up else -1, tot, plen))
        if flags & 0x02:
            f["hs"] |= 1 if not flags & 0x10 else 2        # SYN seen / SYN-ACK seen
        if plen and f["sig"] is None:
            lab, ev = signature(proto, key[1], key[3], payload, plen)
            if lab:
                f["sig"], f["ev"] = lab, ev
            if up and f["first_up"] is None:
                f["first_up"] = payload[:64]
            if not up and f["first_dn"] is None:
                f["first_dn"] = payload[:64]
    out = []
    for (lip, lport, rip, rport, proto), f in flows.items():
        pk = f["pk"]
        n = len(pk)
        up = [p for p in pk if p[1] > 0]
        dn = [p for p in pk if p[1] < 0]
        dur = pk[-1][0] - pk[0][0] if n > 1 else 0.0
        gaps = [b[0] - a[0] for a, b in zip(pk, pk[1:])]
        gaps_up = [b[0] - a[0] for a, b in zip(up, up[1:])]
        mean_gap = statistics.mean(gaps) if gaps else 0
        jitter = statistics.pstdev(gaps_up) * 1000 if len(gaps_up) > 2 else None           # ms
        cv = (statistics.pstdev(gaps_up) / statistics.mean(gaps_up)) if len(gaps_up) > 2 and statistics.mean(gaps_up) > 0 else None
        sizes = [p[2] for p in pk]
        big = sum(1 for s in sizes if s >= 1200) / n
        small = sum(1 for s in sizes if s <= 200) / n
        pps = n / dur if dur > 0 else 0
        by_up, by_dn = sum(p[2] for p in up), sum(p[2] for p in dn)
        # behaviour from timing and size
        if n <= 3:
            beh = "brief"
        elif cv is not None and cv < 0.35 and 20 <= pps <= 120 and 60 <= statistics.mean(sizes) <= 700 and up and dn:
            beh = "real-time media"
        elif big > 0.5 and by_dn > 4 * max(by_up, 1):
            beh = "streaming or download"
        elif big > 0.5 and by_up > 4 * max(by_dn, 1):
            beh = "upload"
        elif small > 0.7 and pps < 2 and dur > 5 and cv is not None and cv < 0.4:
            beh = "keep-alive (steady beat)"
        elif small > 0.7 and up and dn and pps < 40:
            beh = "interactive"
        else:
            beh = "mixed"
        lab = f["sig"]
        ev = dict(f["ev"] or {})
        evtxt = [ev.get("text")] if ev.get("text") else []
        conf = 0.95 if lab else 0.0
        # fall-backs from ports and behaviour, clearly marked as weaker guesses
        if not lab:
            first = f["first_up"] or f["first_dn"] or b""
            ent = entropy(first)
            if proto == "udp" and rport == 443:
                lab, conf = "QUIC (session already running)", 0.6
                evtxt.append("UDP 443 with no long header seen in the window")
            elif proto == "tcp" and rport in (443, 8443):
                lab, conf = "TLS (session already running)", 0.6
                evtxt.append("TCP 443 mid-session")
            elif proto == "udp" and rport == 41641 or lport == 41641:
                lab, conf = "Tailscale (WireGuard)", 0.7
                evtxt.append("Tailscale's port 41641")
            elif proto == "udp" and rport in (51820, 51821):
                lab, conf = "WireGuard (by port)", 0.6
                evtxt.append("WireGuard's usual port")
            elif first and ent > 7.2 and len(first) >= 48:
                lab, conf = "Unknown encrypted", 0.4
                evtxt.append(f"high-entropy payload ({ent:.1f} bits per byte) with no known header")
            elif first:
                lab, conf = "Unknown", 0.2
        if lab and "WireGuard" in lab and rport == 41641 or (lab == "WireGuard" and lport == 41641):
            lab = "Tailscale (WireGuard)"
            evtxt.append("port 41641")
        # a long-lived, busy, two-way flow to one outside address that is not plain web looks like a tunnel
        tunnel = lab in ("WireGuard", "Tailscale (WireGuard)", "OpenVPN (UDP)", "OpenVPN (TCP)", "IPsec (IKEv2)", "IPsec (ESP in UDP)", "IPsec (ESP)", "WireGuard (by port)") \
            or (lab == "DTLS" and dur > 8 and not is_local(rip) and beh not in ("real-time media",))
        if lab == "TLS" and ev.get("sni") and TOR_SNI.match(ev["sni"]) and rport in (443, 9001, 9030):
            lab, tunnel = "Tor (likely)", True
            evtxt.append("random-looking www.*.com server name, the pattern Tor relays use")
        out.append({
            "lan": lip, "lport": lport, "remote": rip, "rport": rport, "proto": proto,
            "label": lab or "Unidentified", "conf": conf, "evidence": [e for e in evtxt if e],
            "sni": ev.get("sni"), "alpn": ev.get("alpn"), "ech": ev.get("ech", False), "pq": ev.get("pq", False),
            "behaviour": beh, "tunnel": bool(tunnel), "encrypted": bool(lab and not lab.startswith(("HTTP", "DNS", "NTP", "Local"))),
            "pkts": n, "pkts_up": len(up), "pkts_dn": len(dn), "bytes_up": by_up, "bytes_dn": by_dn,
            "dur": round(dur, 3), "pps": round(pps, 2), "jitter_ms": round(jitter, 2) if jitter is not None else None,
            "cv": round(cv, 3) if cv is not None else None, "mean_size": round(statistics.mean(sizes), 1),
            "size_sd": round(statistics.pstdev(sizes), 1) if n > 1 else 0.0,
            "trace": [[round(p[0] - pk[0][0], 4), p[1] * p[2]] for p in pk[:160]],    # time and signed size, for the waveform
            "t0": pk[0][0],
        })
    out.sort(key=lambda f: -(f["bytes_up"] + f["bytes_dn"]))
    return {"t0": t_first, "t1": t_last, "flows": out}


# ------------------------------------------------------------------ QUIC Initial decryption (RFC 9001, RFC 9369)
# A QUIC connection's first packets are protected with keys anyone can derive from the packet itself (the salt
# is published in the standard), so the server name inside is readable by anyone on the path, the ISP included.
# These functions decrypt that first packet, as far as the captured slice goes.
_QUIC = {
    0x00000001: (bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), "quic key", "quic iv", "quic hp", 0),
    0x6B3343CF: (bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"), "quicv2 key", "quicv2 iv", "quicv2 hp", 1),
}


def _hkdf_label(secret, label, length):
    """HKDF-Expand-Label from TLS 1.3 with SHA-256."""
    full = b"tls13 " + label.encode()
    info = struct.pack("!HB", length, len(full)) + full + b"\x00"
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def _varint(b, i):
    """A QUIC variable-length integer at offset i: (value, next offset)."""
    n = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for k in range(1, n):
        v = (v << 8) | b[i + k]
    return v, i + n


def quic_initial_pieces(p):
    """(dcid, {offset: bytes}) of the CRYPTO frames in a client QUIC Initial packet, or None."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        return None
    try:
        if len(p) < 40 or not (p[0] & 0x80):
            return None
        ver = struct.unpack("!I", p[1:5])[0]
        if ver not in _QUIC:
            return None
        salt, lk, li, lh, v2 = _QUIC[ver]
        if ((p[0] >> 4) & 3) != (1 if v2 else 0):       # Initial packets only
            return None
        i = 5
        dl = p[i]; dcid = p[i + 1:i + 1 + dl]; i += 1 + dl
        sl = p[i]; i += 1 + sl
        tl, i = _varint(p, i); i += tl
        length, i = _varint(p, i)
        pn_off = i
        initial = hmac.new(salt, dcid, hashlib.sha256).digest()
        csec = _hkdf_label(initial, "client in", 32)
        key, iv, hp = _hkdf_label(csec, lk, 16), _hkdf_label(csec, li, 12), _hkdf_label(csec, lh, 16)
        sample = p[pn_off + 4:pn_off + 20]
        if len(sample) < 16:
            return None
        enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
        mask = enc.update(sample) + enc.finalize()
        pnl = ((p[0] ^ (mask[0] & 0x0F)) & 3) + 1
        pn = int.from_bytes(bytes(a ^ b for a, b in zip(p[pn_off:pn_off + pnl], mask[1:1 + pnl])), "big")
        nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
        end = pn_off + length - 16
        ct = p[pn_off + pnl:end] if len(p) >= end else p[pn_off + pnl:]
        dec = Cipher(algorithms.AES(key), modes.CTR(nonce + b"\x00\x00\x00\x02")).decryptor()   # AES-GCM without the tag check
        pt = dec.update(ct) + dec.finalize()
        pieces, j = {}, 0
        while j < len(pt):
            ft = pt[j]
            if ft in (0x00, 0x01):                        # padding, ping
                j += 1
            elif ft == 0x06:                              # CRYPTO
                off, j = _varint(pt, j + 1)
                ln, j = _varint(pt, j)
                pieces[off] = pt[j:j + ln]
                j += ln
            else:
                break
        return (dcid.hex(), pieces) if pieces else None
    except (IndexError, struct.error, ValueError):
        return None


def assemble_client_hello(pieces):
    """ClientHello from CRYPTO pieces {offset: bytes} collected over one or more Initial packets."""
    buf, at = b"", 0
    while at in pieces and pieces[at]:
        buf += pieces[at]
        at += len(pieces[at])
    if not buf or buf[0] != 0x01:
        return None, False
    need = 4 + int.from_bytes(buf[1:4], "big")
    ch = tls_client_hello(b"\x16\x03\x01" + struct.pack("!H", min(len(buf), 65535)) + buf)
    return ch, len(buf) >= need


def quic_initial_sni(p):
    """The ClientHello facts inside one client QUIC Initial packet, or None."""
    r = quic_initial_pieces(p)
    return assemble_client_hello(r[1])[0] if r else None


if __name__ == "__main__":                                  # python3 dpi.py capture.pcap
    import collections
    import sys
    r = analyse(open(sys.argv[1], "rb").read())
    print(f"{len(r['flows'])} flows over {r['t1'] - r['t0']:.1f} s")
    c = collections.Counter(f["label"] for f in r["flows"])
    print(c.most_common())
    for f in r["flows"]:
        if f["label"] in ("Unidentified",) and f["pkts"] < 3:
            continue
        print(f"{f['lan']:>15}:{f['lport']:<5} -> {f['remote']:>15}:{f['rport']:<5} {f['proto']} {f['label']:28} {f['behaviour']:22} "
              f"pk={f['pkts']:<4} jit={f['jitter_ms']} tun={f['tunnel']} {'; '.join(f['evidence'])[:90]}")
