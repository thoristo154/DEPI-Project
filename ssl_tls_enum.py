#!/usr/bin/env python3
"""
Final SSL/TLS Enumeration Module for Recony
- Robust, accurate detection of supported TLS versions and ciphers
- Strong validation to avoid false-positives caused by negotiation/fallback
- Returns JSON-friendly dict compatible with other Recony modules

Requirements: Python 3.8+ (best results with OpenSSL 1.1.1+)
"""

from __future__ import annotations

import ssl
import socket
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# Helper to detect availability of TLSVersion enum (Python 3.7+/3.8+)
HAS_TLS_VERSION = hasattr(ssl, 'TLSVersion')

class SSLEnumerator:
    DEFAULT_PORTS = [443, 8443, 465, 993, 995, 636]

    # Candidate ciphers for probing. Use names that OpenSSL/Python expect.
    CIPHER_PROBES = [
        # TLS 1.3 style names are negotiated automatically by TLS1.3; probing
        # will rely on the negotiated value returned by the socket.
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_128_GCM_SHA256',
        # TLS 1.2 and earlier cipher-suite names
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES256-SHA',
        'AES256-SHA',
        'CAMELLIA256-SHA',
        'DES-CBC3-SHA',
        'RC4-SHA',
        'RC4-MD5',
        'NULL-SHA'
    ]

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def _create_base_context(self, purpose=ssl.Purpose.SERVER_AUTH) -> ssl.SSLContext:
        """Create a baseline SSLContext for probing. It will be adjusted by callers."""
        # Use CLIENT mode context to get modern defaults
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # Avoid hostname checking and cert verification during scanning
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Try to reduce OpenSSL security level so weak ciphers/protocols can be tested
        # without local policy blocking the handshake. If not supported, continue.
        try:
            ctx.set_ciphers('ALL:@SECLEVEL=0')
        except Exception:
            try:
                ctx.set_ciphers('ALL')
            except Exception:
                # If even this fails, continue with default context ciphers.
                pass

        return ctx

    def _open_tcp(self, host: str, port: int) -> Optional[socket.socket]:
        """Open raw TCP socket (IPv4/IPv6 aware)."""
        try:
            for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
                af, socktype, proto, canonname, sa = res
                try:
                    sock = socket.socket(af, socktype, proto)
                    sock.settimeout(self.timeout)
                    sock.connect(sa)
                    return sock
                except Exception:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    continue
        except Exception:
            return None
        return None

    def create_connection(self, host: str, port: int, context: ssl.SSLContext) -> Optional[ssl.SSLSocket]:
        """Establish TLS handshake using the provided context. Returns SSLSocket or None."""
        raw = None
        try:
            raw = self._open_tcp(host, port)
            if not raw:
                return None

            # Wrap socket using provided context — this will perform handshake
            ssl_sock = context.wrap_socket(raw, server_hostname=host)
            return ssl_sock
        except Exception:
            try:
                if raw:
                    raw.close()
            except Exception:
                pass
            return None

    def retrieve_certificate(self, host: str, port: int) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            'status': 'error',
            'cert_info': {},
            'connection': {},
            'error': None
        }

        ctx = self._create_base_context()
        # Do a normal TLS handshake (allow highest supported versions)
        try:
            sock = self.create_connection(host, port, ctx)
            if not sock:
                result['error'] = 'Connection refused or handshake failed'
                return result

            # Certificate parsing
            try:
                cert_dict = sock.getpeercert(binary_form=False)
                cert_bin = sock.getpeercert(binary_form=True)
            except Exception:
                cert_dict = {}

            try:
                cipher = sock.cipher() or (None, None, 0)
                version = sock.version() or 'Unknown'
            except Exception:
                cipher = (None, None, 0)
                version = 'Unknown'

            if cert_dict:
                # Extract common name and issuer safely
                subject = {}
                issuer = {}
                try:
                    for part in cert_dict.get('subject', ()):  # subject is a sequence of tuples
                        if part and isinstance(part[0], tuple):
                            # e.g. (('commonName','example.com'),)
                            for kv in part:
                                if isinstance(kv, tuple) and len(kv) == 2:
                                    subject[kv[0]] = kv[1]
                        elif part and isinstance(part, tuple):
                            # alternate structure
                            k, v = part
                            subject[k] = v
                except Exception:
                    pass

                try:
                    for part in cert_dict.get('issuer', ()):  # issuer similar to subject
                        if part and isinstance(part[0], tuple):
                            for kv in part:
                                if isinstance(kv, tuple) and len(kv) == 2:
                                    issuer[kv[0]] = kv[1]
                        elif part and isinstance(part, tuple):
                            k, v = part
                            issuer[k] = v
                except Exception:
                    pass

                not_before = cert_dict.get('notBefore')
                not_after = cert_dict.get('notAfter')

                cert_info = {
                    'subject_cn': subject.get('commonName') or subject.get('CN') or None,
                    'issuer_cn': issuer.get('commonName') or issuer.get('CN') or None,
                    'notBefore': not_before,
                    'notAfter': not_after,
                    'serial': cert_dict.get('serialNumber'),
                    'version': cert_dict.get('version')
                }

                # Parse notAfter to compute expiry if possible
                try:
                    if not_after:
                        # Example format: 'Oct  1 00:00:00 2025 GMT'
                        # Use strptime with flexible handling
                        not_after_dt = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        not_after_dt = not_after_dt.replace(tzinfo=timezone.utc)
                        days_left = (not_after_dt - datetime.now(timezone.utc)).days
                        cert_info['days_until_expiry'] = days_left
                        cert_info['expired'] = days_left < 0
                except Exception:
                    # If parsing fails, ignore expiry fields
                    pass

                result['cert_info'] = cert_info

            # Connection meta
            result['connection'] = {
                'version': version,
                'cipher': cipher[0] if cipher and cipher[0] else None,
                'bits': cipher[2] if cipher and len(cipher) > 2 else 0
            }

            result['status'] = 'success'

        except Exception as e:
            result['error'] = str(e)
        finally:
            try:
                sock.close()
            except Exception:
                pass

        return result

    def check_protocols(self, host: str, port: int) -> Dict[str, bool]:
        """Enumerate TLS protocol support by forcing min/max versions per attempt.
        Returns mapping like {'TLSv1.0': False, 'TLSv1.1': False, 'TLSv1.2': True, 'TLSv1.3': True}
        """
        results: Dict[str, bool] = {}

        # Map name to TLSVersion if available, otherwise to fallback handling
        protocol_order = ['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']

        # If TLSVersion enum exists, use it to set min/max. Otherwise attempt with older constants.
        for proto_name in protocol_order:
            try:
                ctx = self._create_base_context()

                if HAS_TLS_VERSION:
                    version_enum = getattr(ssl.TLSVersion, proto_name.replace('TLSv', 'TLSv'))
                    # Force the exact version
                    ctx.minimum_version = version_enum
                    ctx.maximum_version = version_enum
                else:
                    # Older Python: use protocol-specific contexts if available
                    if proto_name == 'TLSv1.0' and hasattr(ssl, 'PROTOCOL_TLSv1'):
                        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                    elif proto_name == 'TLSv1.1' and hasattr(ssl, 'PROTOCOL_TLSv1_1'):
                        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
                    elif proto_name == 'TLSv1.2' and hasattr(ssl, 'PROTOCOL_TLSv1_2'):
                        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    else:
                        # For TLSv1.3 or unsupported older constants, fall back to TLS client context
                        ctx = self._create_base_context()

                # Try to perform a handshake; if the handshake completes, ensure negotiated version matches
                sock = self.create_connection(host, port, ctx)
                if sock:
                    try:
                        negotiated = sock.version() or ''
                        # Normalize names (e.g., 'TLSv1.3')
                        results[proto_name] = negotiated.lower() == proto_name.lower()
                    except Exception:
                        results[proto_name] = False
                    finally:
                        try:
                            sock.close()
                        except Exception:
                            pass
                else:
                    results[proto_name] = False
            except Exception:
                results[proto_name] = False

        return results

    def check_ciphers(self, host: str, port: int) -> List[str]:
        """Probe each cipher and validate the negotiated cipher is exactly the probed one.
        This avoids false positives from fallback negotiation.
        """
        supported: List[str] = []

        for cipher_name in self.CIPHER_PROBES:
            try:
                ctx = self._create_base_context()

                # For probing we allow TLSv1.2+ (TLS1.3 ciphers are negotiated by TLS1.3 handshake)
                if HAS_TLS_VERSION:
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                else:
                    # Rely on default TLS client behavior if TLSVersion is unavailable
                    pass

                # Try to set the single cipher; if library doesn't support the cipher string, skip
                try:
                    ctx.set_ciphers(cipher_name + ':@SECLEVEL=0')
                except Exception:
                    # If setting this exact cipher fails locally, skip probe; this avoids false
                    # reporting due to local OpenSSL inability to represent that cipher.
                    continue

                sock = self.create_connection(host, port, ctx)
                if not sock:
                    continue

                try:
                    negotiated = sock.cipher() or (None, None, 0)
                    negotiated_name = negotiated[0] if negotiated and negotiated[0] else None
                    # For TLS1.3, OpenSSL may report TLS_AES_128_GCM_SHA256 etc. The cipher_name list
                    # includes both TLS1.3 names and TLS1.2-style suites; direct equality is required
                    if negotiated_name and negotiated_name.upper() == cipher_name.upper():
                        supported.append(cipher_name)
                finally:
                    try:
                        sock.close()
                    except Exception:
                        pass
            except Exception:
                continue

        return supported

    def run_full_enum(self, host: str, port: int = 443) -> Dict[str, Any]:
        logger.info('Starting SSL/TLS enumeration for %s:%s', host, port)

        cert_data = self.retrieve_certificate(host, port)
        protocols = self.check_protocols(host, port)
        ciphers = self.check_ciphers(host, port)

        # Assess weaknesses
        weak_protos = [p for p, v in protocols.items() if v and p in ('TLSv1.0', 'TLSv1.1')]
        weak_ciphers = [c for c in ciphers if any(x in c.upper() for x in ('RC4', 'DES', 'NULL'))]

        rating = 'Secure'
        issues: List[str] = []

        if cert_data.get('cert_info', {}).get('expired'):
            rating = 'Critical'
            issues.append('Certificate Expired')

        if weak_protos:
            if rating != 'Critical':
                rating = 'Poor'
            issues.append('Weak Protocols: ' + ', '.join(weak_protos))

        if weak_ciphers:
            rating = 'Critical'
            issues.append('Broken Ciphers: ' + ', '.join(weak_ciphers))

        return {
            'host': host,
            'port': port,
            'status': 'success',
            'certificate': cert_data.get('cert_info', {}),
            'connection_meta': cert_data.get('connection', {}),
            'protocols': protocols,
            'supported_ciphers': ciphers,
            'security_assessment': {
                'rating': rating,
                'issues': issues
            }
        }


def run_module(params: Dict[str, Any]) -> Dict[str, Any]:
    try:
        host = params.get('host') or params.get('target')
        if not host:
            return {'status': 'error', 'error': "Missing 'host' parameter"}

        port = int(params.get('port', 443))
        timeout = int(params.get('timeout', 5))

        scanner = SSLEnumerator(timeout=timeout)
        return scanner.run_full_enum(host, port)
    except Exception as e:
        return {'status': 'error', 'error': str(e)}


if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        print('Usage: ssl_enumerator_module.py <host> [port]')
        sys.exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    import json
    print(json.dumps(run_module({'host': host, 'port': port}), indent=2))
