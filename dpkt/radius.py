# $Id: radius.py 23 2006-11-08 15:45:33Z dugsong $
# -*- coding: utf-8 -*-
"""Remote Authentication Dial-In User Service.

Besides parsing, this module provides offline Message-Authenticator
verification for captured RADIUS/EAP packets (RFC 3579, RFC 2869 section
5.14).  Verification never contacts an authentication server: callers supply
the shared secret for a known endpoint, and only the local packet bytes are
used.  Use verify_radius_packet() for a single packet,
RadiusEndpointVerifier for request/response correlation, or RADIUS.verify()
on an already parsed packet.

Typical capture workflow::

    radius = dpkt.radius.RADIUS(udp.data)       # udp is dpkt.udp.UDP
    result = radius.verify(secret)               # Access-Request
    if result.valid:                             # only a verified packet
        ...                                      # passes this check

For responses, pass the original request's Authenticator, or feed packets
through RadiusEndpointVerifier so the binding is tracked automatically.  A
result of RADIUS_AUTH_UNVERIFIABLE means the capture lacks the context needed
to decide; it must never be treated as a pass.
"""
from __future__ import absolute_import

import hashlib
import hmac
import struct

from . import dpkt
from .compat import compat_ord

try:
    from hmac import compare_digest as _compare_digest
except ImportError:  # Python 2.7
    def _compare_digest(a, b):
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= compat_ord(x) ^ compat_ord(y)
        return result == 0

# http://www.untruth.org/~josh/security/radius/radius-auth.html
# RFC 2865


class RADIUS(dpkt.Packet):
    """Remote Authentication Dial-In User Service.

    Remote Authentication Dial-In User Service (RADIUS) is a networking protocol that provides centralized
    authentication, authorization, and accounting (AAA) management for users who connect and use a network service.
    RADIUS was developed by Livingston Enterprises in 1991 as an access server authentication and accounting protocol.
    It was later brought into IEEE 802 and IETF standards.

    Attributes:
        __hdr__: Header fields of RADIUS.
            code: (int): Code. (1 byte)
            id: (int): ID (1 byte)
            len: (int): Length (2 bytes)
            auth: (int): Authentication (16 bytes)
    """

    __hdr__ = (
        ('code', 'B', 0),
        ('id', 'B', 0),
        ('len', 'H', 4),
        ('auth', '16s', b'')
    )
    attrs = b''
    _raw = b''

    @property
    def raw(self):
        """The exact captured packet bytes (not shown in repr)."""
        return self._raw

    def unpack(self, buf):
        # Keep the exact captured bytes: attribute order and padding matter
        # for Message-Authenticator verification.
        self._raw = buf
        dpkt.Packet.unpack(self, buf)
        self.attrs = parse_attrs(self.data)
        self.data = b''

    def verify(self, secret, request_authenticator=None):
        """Verify this packet's Message-Authenticator offline.

        Args:
            secret: shared secret for the endpoint, as bytes.
            request_authenticator: 16-byte Authenticator of the original
                request when this packet is a response.

        Returns:
            RadiusAuthResult.
        """
        return verify_radius_packet(self.raw, secret, request_authenticator)

    # Explicit alias for callers that prefer the RFC attribute name.
    verify_message_authenticator = verify


def parse_attrs(buf):
    """Parse attributes buffer into a list of (type, data) tuples."""
    attrs = []
    while buf:
        t = compat_ord(buf[0])
        l_ = compat_ord(buf[1])
        if l_ < 2:
            break
        d, buf = buf[2:l_], buf[l_:]
        attrs.append((t, d))
    return attrs


# Codes
RADIUS_ACCESS_REQUEST = 1
RADIUS_ACCESS_ACCEPT = 2
RADIUS_ACCESS_REJECT = 3
RADIUS_ACCT_REQUEST = 4
RADIUS_ACCT_RESPONSE = 5
RADIUS_ACCT_STATUS = 6
RADIUS_ACCESS_CHALLENGE = 11

# Attributes
RADIUS_USER_NAME = 1
RADIUS_USER_PASSWORD = 2
RADIUS_CHAP_PASSWORD = 3
RADIUS_NAS_IP_ADDR = 4
RADIUS_NAS_PORT = 5
RADIUS_SERVICE_TYPE = 6
RADIUS_FRAMED_PROTOCOL = 7
RADIUS_FRAMED_IP_ADDR = 8
RADIUS_FRAMED_IP_NETMASK = 9
RADIUS_FRAMED_ROUTING = 10
RADIUS_FILTER_ID = 11
RADIUS_FRAMED_MTU = 12
RADIUS_FRAMED_COMPRESSION = 13
RADIUS_LOGIN_IP_HOST = 14
RADIUS_LOGIN_SERVICE = 15
RADIUS_LOGIN_TCP_PORT = 16
# unassigned
RADIUS_REPLY_MESSAGE = 18
RADIUS_CALLBACK_NUMBER = 19
RADIUS_CALLBACK_ID = 20
# unassigned
RADIUS_FRAMED_ROUTE = 22
RADIUS_FRAMED_IPX_NETWORK = 23
RADIUS_STATE = 24
RADIUS_CLASS = 25
RADIUS_VENDOR_SPECIFIC = 26
RADIUS_SESSION_TIMEOUT = 27
RADIUS_IDLE_TIMEOUT = 28
RADIUS_TERMINATION_ACTION = 29
RADIUS_CALLED_STATION_ID = 30
RADIUS_CALLING_STATION_ID = 31
RADIUS_NAS_ID = 32
RADIUS_PROXY_STATE = 33
RADIUS_LOGIN_LAT_SERVICE = 34
RADIUS_LOGIN_LAT_NODE = 35
RADIUS_LOGIN_LAT_GROUP = 36
RADIUS_FRAMED_ATALK_LINK = 37
RADIUS_FRAMED_ATALK_NETWORK = 38
RADIUS_FRAMED_ATALK_ZONE = 39
# 40-59 reserved for accounting
RADIUS_CHAP_CHALLENGE = 60
RADIUS_NAS_PORT_TYPE = 61
RADIUS_PORT_LIMIT = 62
RADIUS_LOGIN_LAT_PORT = 63

# RFC 3579 attributes.  The Message-Authenticator attribute itself must be
# 16 bytes long; EAP-Message may be split over several attributes, each capped
# at RADIUS_EAP_MESSAGE_MAX_LEN value bytes.
RADIUS_EAP_MESSAGE = 79
RADIUS_MESSAGE_AUTHENTICATOR = 80
RADIUS_EAP_MESSAGE_MAX_LEN = 253
RADIUS_MESSAGE_AUTHENTICATOR_LEN = 16

# Verification outcomes.  "Unverifiable" (rather than "valid") is used whenever
# the capture does not carry enough trustworthy context to make a decision.
RADIUS_AUTH_VALID = 'valid'
RADIUS_AUTH_INVALID = 'invalid'
RADIUS_AUTH_UNVERIFIABLE = 'unverifiable'


class RadiusAuthResult(object):
    """Outcome of an offline RADIUS Message-Authenticator verification.

    Attributes:
        status: one of RADIUS_AUTH_VALID, RADIUS_AUTH_INVALID or
            RADIUS_AUTH_UNVERIFIABLE.
        reason: stable machine-readable reason code.  Safe to log.
        detail: human-readable explanation; never contains the shared secret.
        id: RADIUS packet identifier, when the packet header was readable.
        code: RADIUS packet code, when the packet header was readable.
        attributes: tuple of (type, value) pairs in wire order, when the
            packet could be parsed.
    """

    def __init__(self, status, reason, detail='', id=None, code=None, attributes=None):
        self.status = status
        self.reason = reason
        self.detail = detail
        self.id = id
        self.code = code
        self.attributes = attributes

    @property
    def valid(self):
        """True only for a cryptographically verified packet."""
        return self.status == RADIUS_AUTH_VALID

    @property
    def verifiable(self):
        """False when context was insufficient to reach a decision."""
        return self.status != RADIUS_AUTH_UNVERIFIABLE

    def __bool__(self):
        return self.valid

    __nonzero__ = __bool__

    def __repr__(self):
        return '%s(status=%r, reason=%r)' % (
            self.__class__.__name__, self.status, self.reason)


class RadiusPacketContext(object):
    """The information needed to verify one RADIUS packet.

    For an Access-Request the packet's own Authenticator is used.  For a
    response the Authenticator of the original request must be supplied as
    request_authenticator (RFC 3579 section 3.2).

    Attributes:
        code: RADIUS packet code.
        id: RADIUS packet identifier.
        raw: the complete packet bytes, exactly as captured (header included).
        request_authenticator: 16-byte Authenticator of the original request
            for response packets; ignored for requests.
    """

    def __init__(self, code, id, raw, request_authenticator=None):
        self.code = code
        self.id = id
        self.raw = raw
        self.request_authenticator = request_authenticator

    def __repr__(self):
        return '%s(code=%r, id=%r)' % (self.__class__.__name__, self.code, self.id)


def _is_request_code(code):
    return code == RADIUS_ACCESS_REQUEST


def _is_response_code(code):
    return code in (RADIUS_ACCESS_ACCEPT, RADIUS_ACCESS_REJECT,
                    RADIUS_ACCESS_CHALLENGE)


def _split_raw_attrs(raw, offset, end):
    """Split raw TLV bytes without normalizing or reordering them.

    Returns (attributes, error).  Each attribute is (type, value, start, stop)
    with start/stop indexing the complete attribute bytes in raw.
    """
    attrs = []
    pos = offset
    while pos < end:
        if end - pos < 2:
            return attrs, 'truncated_attribute_header'
        t = compat_ord(raw[pos])
        l_ = compat_ord(raw[pos + 1])
        if l_ < 2:
            return attrs, 'invalid_attribute_length'
        if pos + l_ > end:
            return attrs, 'attribute_exceeds_packet'
        attrs.append((t, raw[pos + 2:pos + l_], pos, pos + l_))
        pos += l_
    return attrs, None


def _build_auth_message(raw, declared_len, request_authenticator):
    """Return the exact bytes covered by Message-Authenticator.

    RFC 3579 section 3.2: for a response, the Authenticator field in the
    packet is replaced with the Request Authenticator for the calculation.
    The Message-Authenticator attribute value is treated as zero.  Attribute
    order and every other byte are preserved; nothing is re-serialized.
    """
    msg = bytearray(raw[:declared_len])
    if request_authenticator is not None:
        msg[4:20] = request_authenticator
    for t, value, start, _ in _split_raw_attrs(raw, 20, declared_len)[0]:
        if t == RADIUS_MESSAGE_AUTHENTICATOR:
            msg[start + 2:start + 2 + len(value)] = b'\x00' * len(value)
    return bytes(msg)


def verify_message_authenticator(context, secret, request_authenticator=None):
    """Verify one RADIUS packet offline against a known shared secret.

    No network access is performed.  The packet bytes are used exactly as
    captured, including declared length, attribute order and duplicate
    attributes.  Message-Authenticator is checked per RFC 3579/2869.

    Args:
        context: RadiusPacketContext, or the complete raw packet bytes.
        secret: shared secret as bytes (or text on Python 3).
        request_authenticator: for a response, the 16-byte Authenticator of
            the original request.  Only used when context is raw bytes.

    Returns:
        RadiusAuthResult.  Missing or contradictory context yields
        RADIUS_AUTH_UNVERIFIABLE, never RADIUS_AUTH_VALID.
    """
    if not isinstance(context, RadiusPacketContext):
        if isinstance(context, (bytes, bytearray)):
            raw = bytes(context)
            if len(raw) < 4:
                return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE,
                                        'truncated_header',
                                        'packet is shorter than the RADIUS header')
            code, ident = struct.unpack('>BB', raw[:2])
            context = RadiusPacketContext(code, ident, raw,
                                          request_authenticator)
        else:
            return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE, 'invalid_context',
                                    'context must be a RadiusPacketContext')

    if isinstance(secret, bytes):
        pass  # includes str on Python 2; never re-encode raw secret bytes
    elif isinstance(secret, str):
        secret = secret.encode('utf-8')
    else:
        return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE, 'invalid_secret',
                                'shared secret must be bytes')
    if not secret:
        return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE, 'invalid_secret',
                                'shared secret is empty')

    raw = context.raw
    if isinstance(raw, bytearray):
        raw = bytes(raw)
    if not isinstance(raw, bytes):
        return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE, 'invalid_context',
                                'raw packet must be bytes')
    if len(raw) < 4:
        return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE, 'truncated_header',
                                'packet is shorter than the RADIUS header')
    code, ident, declared_len = struct.unpack('>BBH', raw[:4])

    attrs = None
    if len(raw) >= 20:
        attrs, _ = _split_raw_attrs(raw, 20, min(len(raw), declared_len))
    if (code, ident) != (context.code, context.id):
        return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE, 'context_mismatch',
                                'context code/id do not match the raw packet',
                                ident, code, _attr_pairs(attrs))

    if declared_len < 20 or declared_len > 4096:
        return RadiusAuthResult(RADIUS_AUTH_INVALID, 'declared_length_invalid',
                                'declared packet length is out of range',
                                ident, code, _attr_pairs(attrs))
    if len(raw) < 20 or declared_len > len(raw):
        # Capture was truncated (e.g. pcap snaplen): the bytes covered by the
        # HMAC are not all present, so no decision can be made.
        return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE, 'truncated_capture',
                                'declared length exceeds captured bytes',
                                ident, code, _attr_pairs(attrs))
    if declared_len != len(raw):
        return RadiusAuthResult(RADIUS_AUTH_INVALID,
                                'declared_length_mismatch',
                                'captured bytes exceed the declared packet length',
                                ident, code, _attr_pairs(attrs))

    attrs, attr_error = _split_raw_attrs(raw, 20, declared_len)
    if attr_error is not None:
        return RadiusAuthResult(RADIUS_AUTH_INVALID, attr_error,
                                'malformed attribute list', ident, code,
                                _attr_pairs(attrs))

    if not _is_request_code(code) and not _is_response_code(code):
        return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE, 'unsupported_code',
                                'packet code is not covered by RFC 3579',
                                ident, code, _attr_pairs(attrs))

    if _is_response_code(code):
        req_auth = context.request_authenticator
        if req_auth is None:
            return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE,
                                    'missing_request_authenticator',
                                    'response requires the original request Authenticator',
                                    ident, code, _attr_pairs(attrs))
        if not isinstance(req_auth, bytes) or len(req_auth) != 16:
            return RadiusAuthResult(RADIUS_AUTH_INVALID,
                                    'request_authenticator_invalid',
                                    'request Authenticator must be 16 bytes',
                                    ident, code, _attr_pairs(attrs))
        auth_message = _build_auth_message(raw, declared_len, req_auth)
    else:
        if context.request_authenticator is not None:
            return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE,
                                    'context_mismatch',
                                    'request packets must not be bound to another request',
                                    ident, code, _attr_pairs(attrs))
        auth_message = _build_auth_message(raw, declared_len, None)

    msg_auth_attrs = [a for a in attrs if a[0] == RADIUS_MESSAGE_AUTHENTICATOR]
    for _, value, _, _ in msg_auth_attrs:
        if len(value) != RADIUS_MESSAGE_AUTHENTICATOR_LEN:
            return RadiusAuthResult(RADIUS_AUTH_INVALID,
                                    'message_authenticator_length',
                                    'Message-Authenticator must be 16 bytes',
                                    ident, code, _attr_pairs(attrs))
    if not msg_auth_attrs:
        if _has_eap_message(attrs):
            return RadiusAuthResult(RADIUS_AUTH_INVALID,
                                    'missing_message_authenticator',
                                    'EAP-Message requires Message-Authenticator',
                                    ident, code, _attr_pairs(attrs))
        return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE, 'no_message_authenticator',
                                'packet has no Message-Authenticator to verify',
                                ident, code, _attr_pairs(attrs))
    if len(msg_auth_attrs) > 1:
        return RadiusAuthResult(RADIUS_AUTH_INVALID,
                                'duplicate_message_authenticator',
                                'more than one Message-Authenticator attribute',
                                ident, code, _attr_pairs(attrs))

    expected = hmac.new(secret, auth_message, hashlib.md5).digest()
    actual = msg_auth_attrs[0][1]
    if not _compare_digest(expected, actual):
        return RadiusAuthResult(RADIUS_AUTH_INVALID,
                                'message_authenticator_mismatch',
                                'Message-Authenticator does not match',
                                ident, code, _attr_pairs(attrs))
    return RadiusAuthResult(RADIUS_AUTH_VALID, 'message_authenticator_ok',
                            'Message-Authenticator verified', ident, code,
                            _attr_pairs(attrs))


def _attr_pairs(attrs):
    if attrs is None:
        return None
    return tuple((t, value) for t, value, _, _ in attrs)


def _has_eap_message(attrs):
    return any(t == RADIUS_EAP_MESSAGE for t, _, _, _ in attrs)


_AMBIGUOUS_REQUEST = object()


class RadiusEndpointVerifier(object):
    """Stateful, offline RADIUS verifier for one known endpoint pair.

    Requests are recorded so later responses can be bound to the correct
    Request Authenticator.  Identifier reuse before a response is observed is
    reported as unverifiable instead of guessed.  All state is local to this
    object; no authentication server is contacted.

    Args:
        secret: shared secret for this endpoint, as bytes.
    """

    def __init__(self, secret):
        self._secret = secret
        self._pending = {}

    @staticmethod
    def _normalize_secret(secret):
        if isinstance(secret, bytes):
            return secret
        if isinstance(secret, str):
            return secret.encode('utf-8')
        return None

    def reset(self):
        """Forget all recorded request contexts."""
        self._pending = {}

    def observe(self, context):
        """Verify a packet and update request/response correlation state.

        Returns RadiusAuthResult.  A response whose Request Authenticator
        cannot be established unambiguously is RADIUS_AUTH_UNVERIFIABLE.
        """
        if not isinstance(context, RadiusPacketContext):
            return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE, 'invalid_context',
                                    'context must be a RadiusPacketContext')
        if self._normalize_secret(self._secret) is None:
            return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE, 'invalid_secret',
                                    'shared secret must be bytes')
        raw = context.raw
        if isinstance(raw, bytearray):
            context = RadiusPacketContext(context.code, context.id, bytes(raw),
                                          context.request_authenticator)
            raw = context.raw
        if not isinstance(raw, bytes) or len(raw) < 4:
            return verify_message_authenticator(context, self._secret)

        header = struct.unpack('>BBH', raw[:4])
        code, ident, declared_len = header
        if code != context.code or ident != context.id:
            return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE, 'context_mismatch',
                                    'context code/id do not match the raw packet',
                                    context.id, context.code)
        if code == RADIUS_ACCESS_REQUEST and context.request_authenticator is None:
            if len(raw) < 20:
                return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE,
                                        'truncated_header',
                                        'packet is shorter than the RADIUS header',
                                        ident, code)
            pending = self._pending.get(ident)
            if pending is not None:
                if pending is _AMBIGUOUS_REQUEST:
                    return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE, 'id_reuse',
                                            'request id was already reused and is ambiguous',
                                            ident, code)
                if pending[0] != raw:
                    # A different request reuses an unanswered identifier; the
                    # response context can no longer be tied to one request.
                    self._pending[ident] = _AMBIGUOUS_REQUEST
                    return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE, 'id_reuse',
                                            'request id reused before a response was observed',
                                            ident, code)
                # Identical retransmission: keep the original pending context.
                return verify_message_authenticator(context, self._secret)
            result = verify_message_authenticator(context, self._secret)
            if result.status != RADIUS_AUTH_UNVERIFIABLE:
                # Record the identifier even for a failed verification: the
                # request still occupied it.  Only a verified request, though,
                # may later serve as response context.
                self._pending[ident] = (raw, result.status == RADIUS_AUTH_VALID)
            return result

        if _is_response_code(code) and context.request_authenticator is None:
            pending = self._pending.get(ident)
            if pending is None:
                return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE,
                                        'unknown_request_context',
                                        'no verified request context for this response id',
                                        ident, code)
            if pending is _AMBIGUOUS_REQUEST:
                # The response closes whichever request held this id; release
                # it but never claim the response itself was verified.
                del self._pending[ident]
                return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE,
                                        'ambiguous_request_context',
                                        'response id matches more than one request context',
                                        ident, code)
            request_raw, request_verified = pending
            if not request_verified:
                return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE,
                                        'unverified_request_context',
                                        'the request for this id did not verify',
                                        ident, code)
            if len(request_raw) < 20 or declared_len < 20 or \
                    struct.unpack('>BBH', request_raw[:4])[2] != len(request_raw):
                return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE,
                                        'invalid_request_context',
                                        'recorded request context is malformed',
                                        ident, code)
            context = RadiusPacketContext(context.code, context.id, context.raw,
                                          request_raw[4:20])
            result = verify_message_authenticator(context, self._secret)
            if result.status == RADIUS_AUTH_VALID:
                self._pending.pop(ident, None)
            return result
        return verify_message_authenticator(context, self._secret)

    def observe_raw(self, raw, request_authenticator=None):
        """Convenience wrapper taking raw packet bytes."""
        if isinstance(raw, bytearray):
            raw = bytes(raw)
        if not isinstance(raw, bytes) or len(raw) < 4:
            return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE, 'truncated_header',
                                    'packet is shorter than the RADIUS header')
        code, ident = struct.unpack('>BB', raw[:2])
        return self.observe(RadiusPacketContext(code, ident, raw,
                                                request_authenticator))


def verify_radius_packet(raw, secret, request_authenticator=None):
    """Verify raw RADIUS packet bytes offline against a known shared secret.

    This is the stateless entry point; use RadiusEndpointVerifier when
    responses must be matched against previously observed requests.

    Args:
        raw: complete captured RADIUS packet bytes (header included).
        secret: shared secret as bytes, or text that will be UTF-8 encoded.
        request_authenticator: for responses, the 16-byte Authenticator of
            the corresponding request.

    Returns:
        RadiusAuthResult.
    """
    if isinstance(raw, bytearray):
        raw = bytes(raw)
    if not isinstance(raw, bytes) or len(raw) < 4:
        return RadiusAuthResult(RADIUS_AUTH_UNVERIFIABLE, 'truncated_header',
                                'packet is shorter than the RADIUS header')
    code, ident = struct.unpack('>BB', raw[:2])
    return verify_message_authenticator(
        RadiusPacketContext(code, ident, raw, request_authenticator), secret)


def test_parse_attrs():
    from binascii import unhexlify
    buf = unhexlify(
        '01'        # type (RADIUS_USER_NAME)
        '06'        # end of attribute value
        '75736572'  # value ('user')

        '00'
        '00'
    )

    attrs = parse_attrs(buf)
    assert len(attrs) == 1

    type0, value0 = attrs[0]
    assert type0 == RADIUS_USER_NAME
    assert value0 == b'user'


def test_parse_multiple_attrs():
    from binascii import unhexlify
    buf = unhexlify(
        '01'                # type (RADIUS_USER_NAME)
        '06'                # end of attribute value
        '75736572'          # value ('user')

        '02'                # type (RADIUS_USER_PASSWORD)
        '0a'                # end of attribute value
        '70617373776f7264'  # value ('password')
    )

    attrs = parse_attrs(buf)
    assert len(attrs) == 2

    type0, value0 = attrs[0]
    assert type0 == RADIUS_USER_NAME
    assert value0 == b'user'

    type1, value1 = attrs[1]
    assert type1 == RADIUS_USER_PASSWORD
    assert value1 == b'password'


def test_radius_unpacking():
    from binascii import unhexlify
    buf_attrs = unhexlify(
        '01'                # type (RADIUS_USER_NAME)
        '06'                # end of attribute value
        '75736572'          # value ('user')
    )
    buf_radius_header = unhexlify(
        '01'                # code
        '34'                # id
        '1234'              # len
        '0123456789abcdef'  # auth
        '0123456789abcdef'  # auth
    )
    buf = buf_radius_header + buf_attrs
    radius = RADIUS(buf)
    assert len(radius.attrs) == 1
    name0, value0 = radius.attrs[0]
    assert name0 == 1
    assert value0 == b'user'


# ---- Offline Message-Authenticator verification tests ---------------------

def _test_hmac_md5(secret, message):
    """Sign a vector with the standard library HMAC-MD5 implementation."""
    return hmac.new(secret, message, hashlib.md5).digest()


def _test_attr(t, value):
    return struct.pack('>BB', t, len(value) + 2) + value


def _test_signed_packet(code, ident, authenticator, attrs, secret,
                        request_authenticator=None):
    """Build a packet, filling Message-Authenticator using raw-byte HMAC.

    The Message-Authenticator placeholder is added last; all other attributes
    keep the caller's order and bytes.  Only the placeholder value is
    replaced, which mirrors what a signer does.
    """
    attrs = attrs + _test_attr(RADIUS_MESSAGE_AUTHENTICATOR, b'\x00' * 16)
    declared_len = 20 + len(attrs)
    hdr = struct.pack('>BBH', code, ident, declared_len) + authenticator
    msg = hdr + attrs
    if request_authenticator is not None:
        msg = msg[:4] + request_authenticator + msg[20:]
    expected = _test_hmac_md5(secret, msg)
    signed = hdr + attrs[:-18] + _test_attr(RADIUS_MESSAGE_AUTHENTICATOR, expected)
    return signed


def test_verify_valid_access_request():
    secret = b'audit-shared-secret'
    request_auth = bytes(bytearray(range(16)))
    attrs = (_test_attr(RADIUS_USER_NAME, b'audituser')
             + _test_attr(RADIUS_EAP_MESSAGE, b'\x02\x01\x00\x05\x01')
             + _test_attr(RADIUS_NAS_IP_ADDR, b'\x0a\x00\x00\x01'))
    raw = _test_signed_packet(RADIUS_ACCESS_REQUEST, 0x2a, request_auth,
                              attrs, secret)
    result = verify_radius_packet(raw, secret)
    assert result.status == RADIUS_AUTH_VALID
    assert result.reason == 'message_authenticator_ok'
    assert result.valid and result.verifiable
    assert [t for t, _ in result.attributes] == [
        RADIUS_USER_NAME, RADIUS_EAP_MESSAGE, RADIUS_NAS_IP_ADDR,
        RADIUS_MESSAGE_AUTHENTICATOR]


def test_verify_valid_response_bound_to_request():
    secret = b'audit-shared-secret'
    request_auth = bytes(bytearray(range(16, 32)))
    response_auth = bytes(bytearray(reversed(range(16))))
    attrs = _test_attr(RADIUS_EAP_MESSAGE, b'\x03\x01\x00\x04')
    raw = _test_signed_packet(RADIUS_ACCESS_ACCEPT, 0x2a, response_auth,
                              attrs, secret, request_auth)
    result = verify_radius_packet(raw, secret, request_authenticator=request_auth)
    assert result.status == RADIUS_AUTH_VALID

    wrong_request_auth = bytes(bytearray(range(32, 48)))
    wrong = verify_radius_packet(raw, secret,
                                 request_authenticator=wrong_request_auth)
    assert wrong.status == RADIUS_AUTH_INVALID
    assert wrong.reason == 'message_authenticator_mismatch'


def test_verify_response_without_request_context_is_unverifiable():
    secret = b'audit-shared-secret'
    request_auth = bytes(bytearray(range(16)))
    response_auth = bytes(bytearray(range(16, 32)))
    raw = _test_signed_packet(RADIUS_ACCESS_ACCEPT, 9, response_auth,
                              _test_attr(RADIUS_EAP_MESSAGE, b'\x03'), secret,
                              request_auth)
    result = verify_radius_packet(raw, secret)
    assert result.status == RADIUS_AUTH_UNVERIFIABLE
    assert result.reason == 'missing_request_authenticator'
    assert not result.valid and not result.verifiable


def test_verify_tampered_attribute_is_invalid():
    secret = b'audit-shared-secret'
    request_auth = bytes(bytearray(range(16)))
    raw = _test_signed_packet(RADIUS_ACCESS_REQUEST, 7, request_auth,
                              _test_attr(RADIUS_USER_NAME, b'audituser'), secret)
    tampered = bytearray(raw)
    index = tampered.index(b'audituser')
    tampered[index] = 0x41  # 'A'
    result = verify_radius_packet(bytes(tampered), secret)
    assert result.status == RADIUS_AUTH_INVALID
    assert result.reason == 'message_authenticator_mismatch'


def test_verify_other_request_context_is_invalid():
    secret = b'audit-shared-secret'
    request_a = bytes(bytearray(range(16)))
    request_b = bytes(bytearray(range(16, 32)))
    response_auth = bytes(bytearray([0xa5] * 16))
    raw = _test_signed_packet(RADIUS_ACCESS_ACCEPT, 3, response_auth,
                              _test_attr(RADIUS_EAP_MESSAGE, b'\x03'), secret,
                              request_a)
    assert verify_radius_packet(raw, secret, request_authenticator=request_a).valid
    other = verify_radius_packet(raw, secret, request_authenticator=request_b)
    assert other.status == RADIUS_AUTH_INVALID


def test_verify_declared_length_mismatch_is_invalid():
    secret = b'secret'
    raw = _test_signed_packet(RADIUS_ACCESS_REQUEST, 1,
                              bytes(bytearray(range(16))),
                              _test_attr(RADIUS_USER_NAME, b'user'), secret)
    assert verify_radius_packet(raw, secret).valid
    # Declared length one byte shorter than the captured data: the packet can
    # never be a faithful capture of a valid RADIUS message.
    bad = bytearray(raw)
    bad[2:4] = struct.pack('>H', struct.unpack('>H', raw[2:4])[0] - 1)
    result = verify_radius_packet(bytes(bad), secret)
    assert result.status == RADIUS_AUTH_INVALID
    assert result.reason == 'declared_length_mismatch'


def test_verify_truncated_capture_is_unverifiable():
    secret = b'secret'
    raw = _test_signed_packet(RADIUS_ACCESS_REQUEST, 1,
                              bytes(bytearray(range(16))),
                              _test_attr(RADIUS_USER_NAME, b'user'), secret)
    result = verify_radius_packet(raw[:12], secret)
    assert result.status == RADIUS_AUTH_UNVERIFIABLE
    assert result.reason == 'truncated_capture'


def test_verify_duplicate_message_authenticator_is_invalid():
    secret = b'secret'
    auth = bytes(bytearray(range(16)))
    raw = _test_signed_packet(RADIUS_ACCESS_REQUEST, 2, auth,
                              _test_attr(RADIUS_USER_NAME, b'user'), secret)
    duplicated = raw + raw[-18:]
    declared = len(duplicated)
    duplicated = duplicated[:2] + struct.pack('>H', declared) + duplicated[4:]
    result = verify_radius_packet(duplicated, secret)
    assert result.status == RADIUS_AUTH_INVALID
    assert result.reason == 'duplicate_message_authenticator'


def test_verify_eap_message_requires_message_authenticator():
    secret = b'secret'
    auth = bytes(bytearray(range(16)))
    attrs = _test_attr(RADIUS_EAP_MESSAGE, b'\x02\x01')
    raw = struct.pack('>BBH', RADIUS_ACCESS_REQUEST, 4, 20 + len(attrs)) + auth + attrs
    result = verify_radius_packet(raw, secret)
    assert result.status == RADIUS_AUTH_INVALID
    assert result.reason == 'missing_message_authenticator'


def test_verify_without_message_authenticator_is_unverifiable():
    secret = b'secret'
    auth = bytes(bytearray(range(16)))
    attrs = _test_attr(RADIUS_USER_NAME, b'user')
    raw = struct.pack('>BBH', RADIUS_ACCESS_REQUEST, 5, 20 + len(attrs)) + auth + attrs
    result = verify_radius_packet(raw, secret)
    assert result.status == RADIUS_AUTH_UNVERIFIABLE
    assert result.reason == 'no_message_authenticator'


def test_endpoint_verifier_binds_response_and_detects_id_reuse():
    secret = b'audit-shared-secret'
    request_auth = bytes(bytearray(range(16)))
    response_auth = bytes(bytearray(range(16, 32)))
    request = _test_signed_packet(RADIUS_ACCESS_REQUEST, 0x11, request_auth,
                                  _test_attr(RADIUS_USER_NAME, b'user'), secret)
    response = _test_signed_packet(RADIUS_ACCESS_ACCEPT, 0x11, response_auth,
                                   _test_attr(RADIUS_EAP_MESSAGE, b'\x03'),
                                   secret, request_auth)
    verifier = RadiusEndpointVerifier(secret)
    assert verifier.observe_raw(request).valid
    assert verifier.observe_raw(response).valid
    assert not verifier.observe_raw(response).valid
    assert verifier.observe_raw(response).reason == 'unknown_request_context'


def test_endpoint_verifier_id_reuse_is_unverifiable():
    secret = b'secret'
    auth_a = bytes(bytearray(range(16)))
    auth_b = bytes(bytearray(range(16, 32)))
    first = _test_signed_packet(RADIUS_ACCESS_REQUEST, 0x22, auth_a,
                                _test_attr(RADIUS_USER_NAME, b'a'), secret)
    second = _test_signed_packet(RADIUS_ACCESS_REQUEST, 0x22, auth_b,
                                 _test_attr(RADIUS_USER_NAME, b'b'), secret)
    verifier = RadiusEndpointVerifier(secret)
    assert verifier.observe_raw(first).valid
    result = verifier.observe_raw(second)
    assert result.status == RADIUS_AUTH_UNVERIFIABLE
    assert result.reason == 'id_reuse'
    response_auth = bytes(bytearray([0x5a] * 16))
    response = _test_signed_packet(RADIUS_ACCESS_ACCEPT, 0x22, response_auth,
                                   _test_attr(RADIUS_EAP_MESSAGE, b'\x03'),
                                   secret, auth_b)
    ambiguous = verifier.observe_raw(response)
    assert ambiguous.status == RADIUS_AUTH_UNVERIFIABLE
    assert ambiguous.reason == 'ambiguous_request_context'


def test_auth_result_does_not_expose_secret():
    secret = b'audit-shared-secret'
    raw = _test_signed_packet(RADIUS_ACCESS_REQUEST, 6,
                              bytes(bytearray(range(16))),
                              _test_attr(RADIUS_USER_NAME, b'user'), secret)
    result = verify_radius_packet(raw, secret)
    text = repr(result) + ' ' + result.reason + ' ' + result.detail
    assert secret.decode('utf-8') not in text
    # Log-style formatting of the result must not include secret material.
    assert secret.decode('utf-8') not in str(result)
    assert secret.decode('utf-8') not in repr(result.attributes)


def test_verify_preserves_non_standard_attribute_order():
    secret = b'order-matters'
    request_auth = bytes(bytearray(range(16, 32)))
    attrs = (_test_attr(RADIUS_MESSAGE_AUTHENTICATOR, b'\x00' * 16)
             + _test_attr(RADIUS_USER_NAME, b'orderuser')
             + _test_attr(RADIUS_EAP_MESSAGE, b'\x02\x01'))
    declared_len = 20 + len(attrs)
    hdr = struct.pack('>BBH', RADIUS_ACCESS_REQUEST, 8, declared_len) + request_auth
    covered = hdr + attrs
    expected = _test_hmac_md5(secret, covered)
    # Message-Authenticator first, not last: a verifier that sorts or
    # re-serializes attributes would compute a different value.
    signed = hdr + _test_attr(RADIUS_MESSAGE_AUTHENTICATOR, expected) + attrs[18:]
    result = verify_radius_packet(signed, secret)
    assert result.status == RADIUS_AUTH_VALID
    assert [t for t, _ in result.attributes] == [
        RADIUS_MESSAGE_AUTHENTICATOR, RADIUS_USER_NAME, RADIUS_EAP_MESSAGE]


def test_parsed_packet_verify_uses_original_bytes():
    secret = b'parsed-bytes'
    request_auth = bytes(bytearray(range(16)))
    raw = _test_signed_packet(RADIUS_ACCESS_REQUEST, 10, request_auth,
                              _test_attr(RADIUS_USER_NAME, b'user'), secret)
    parsed = RADIUS(raw)
    assert parsed.raw == raw
    assert parsed.verify(secret).valid
    assert parsed.verify(b'wrong').status == RADIUS_AUTH_INVALID


def test_endpoint_verifier_does_not_bind_unverified_request():
    secret = b'secret'
    auth = bytes(bytearray(range(16)))
    request = _test_signed_packet(RADIUS_ACCESS_REQUEST, 0x33, auth,
                                  _test_attr(RADIUS_USER_NAME, b'user'), secret)
    response = _test_signed_packet(RADIUS_ACCESS_ACCEPT, 0x33,
                                   bytes(bytearray([0x77] * 16)),
                                   _test_attr(RADIUS_EAP_MESSAGE, b'\x03'),
                                   secret, auth)
    verifier = RadiusEndpointVerifier(b'wrong-secret')
    result = verifier.observe_raw(request)
    assert result.status == RADIUS_AUTH_INVALID
    bound = verifier.observe_raw(response)
    assert bound.status == RADIUS_AUTH_UNVERIFIABLE
    assert bound.reason == 'unverified_request_context'


def test_endpoint_verifier_retransmission_is_not_id_reuse():
    secret = b'secret'
    request = _test_signed_packet(RADIUS_ACCESS_REQUEST, 0x44,
                                  bytes(bytearray(range(16))),
                                  _test_attr(RADIUS_USER_NAME, b'user'), secret)
    verifier = RadiusEndpointVerifier(secret)
    assert verifier.observe_raw(request).valid
    assert verifier.observe_raw(request).valid


def test_endpoint_verifier_uses_request_authenticator_of_original_request():
    secret = b'secret'
    first_auth = bytes(bytearray(range(16)))
    second_auth = bytes(bytearray(range(16, 32)))
    first = _test_signed_packet(RADIUS_ACCESS_REQUEST, 0x55, first_auth,
                                _test_attr(RADIUS_USER_NAME, b'one'), secret)
    second = _test_signed_packet(RADIUS_ACCESS_REQUEST, 0x55, second_auth,
                                 _test_attr(RADIUS_USER_NAME, b'two'), secret)
    response_auth = bytes(bytearray([0x99] * 16))
    response = _test_signed_packet(RADIUS_ACCESS_ACCEPT, 0x55, response_auth,
                                   _test_attr(RADIUS_EAP_MESSAGE, b'\x03'),
                                   secret, second_auth)
    verifier = RadiusEndpointVerifier(secret)
    assert verifier.observe_raw(first).valid
    verifier.observe_raw(second)  # id reuse: ambiguous from here on
    assert verifier.observe_raw(response).status == RADIUS_AUTH_UNVERIFIABLE


def test_endpoint_verifier_after_response_allows_id_reuse():
    secret = b'secret'
    first_auth = bytes(bytearray(range(16)))
    second_auth = bytes(bytearray(range(16, 32)))
    first = _test_signed_packet(RADIUS_ACCESS_REQUEST, 0x66, first_auth,
                                _test_attr(RADIUS_USER_NAME, b'one'), secret)
    second = _test_signed_packet(RADIUS_ACCESS_REQUEST, 0x66, second_auth,
                                 _test_attr(RADIUS_USER_NAME, b'two'), secret)
    response_auth = bytes(bytearray([0x11] * 16))
    first_response = _test_signed_packet(RADIUS_ACCESS_ACCEPT, 0x66,
                                         response_auth,
                                         _test_attr(RADIUS_EAP_MESSAGE, b'\x03'),
                                         secret, first_auth)
    verifier = RadiusEndpointVerifier(secret)
    assert verifier.observe_raw(first).valid
    assert verifier.observe_raw(first_response).valid
    # A new request may now reuse the identifier; its response binds to it.
    assert verifier.observe_raw(second).valid
    second_response = _test_signed_packet(RADIUS_ACCESS_REJECT, 0x66,
                                          bytes(bytearray([0x22] * 16)),
                                          _test_attr(RADIUS_REPLY_MESSAGE, b'no'),
                                          secret, second_auth)
    assert verifier.observe_raw(second_response).valid


def test_hmac_construction_matches_rfc2202_vector():
    # RFC 2202 test case 2: independent anchor for the vector signer.
    assert _test_hmac_md5(b'Jefe', b'what do ya want for nothing?') == \
        bytes(bytearray.fromhex('750c783e6ab0b503eaa86e310a5db738'))
    raw = _test_signed_packet(RADIUS_ACCESS_REQUEST, 11,
                              bytes(bytearray(range(16))),
                              _test_attr(RADIUS_USER_NAME, b'jefe'), b'Jefe')
    assert verify_radius_packet(raw, b'Jefe').valid


def test_endpoint_verifier_releases_ambiguous_id_on_response():
    secret = b'secret'
    first = _test_signed_packet(RADIUS_ACCESS_REQUEST, 0x77,
                                bytes(bytearray(range(16))),
                                _test_attr(RADIUS_USER_NAME, b'one'), secret)
    second = _test_signed_packet(RADIUS_ACCESS_REQUEST, 0x77,
                                 bytes(bytearray(range(16, 32))),
                                 _test_attr(RADIUS_USER_NAME, b'two'), secret)
    verifier = RadiusEndpointVerifier(secret)
    assert verifier.observe_raw(first).valid
    assert verifier.observe_raw(second).reason == 'id_reuse'
    response = _test_signed_packet(RADIUS_ACCESS_ACCEPT, 0x77,
                                   bytes(bytearray([0x33] * 16)),
                                   _test_attr(RADIUS_EAP_MESSAGE, b'\x03'),
                                   secret, bytes(bytearray(range(16, 32))))
    assert verifier.observe_raw(response).reason == 'ambiguous_request_context'
    # Once the ambiguous exchange is closed, the id is free again.
    reused = _test_signed_packet(RADIUS_ACCESS_REQUEST, 0x77,
                                 bytes(bytearray(range(32, 48))),
                                 _test_attr(RADIUS_USER_NAME, b'two'), secret)
    assert verifier.observe_raw(reused).valid


def test_verify_accepts_bytearray_input():
    raw = bytearray(_test_signed_packet(RADIUS_ACCESS_REQUEST, 12,
                                        bytes(bytearray(range(16))),
                                        _test_attr(RADIUS_USER_NAME, b'user'),
                                        b'secret'))
    assert verify_radius_packet(raw, b'secret').valid
    assert verify_message_authenticator(raw, b'secret').valid
    assert RadiusEndpointVerifier(b'secret').observe_raw(raw).valid
