# -*- coding: utf-8 -*-
"""TLS ClientHello fingerprint extraction that keeps anomalies visible.

The goal of this module is to turn a *single, complete* ClientHello handshake
message into three distinct products without letting normalization hide
malformed input:

1. **Raw ordered features** -- every vector exactly as it appeared on the
   wire, in wire order, including duplicates, empty extensions and the
   original positions of GREASE values.
2. **A stable fingerprint** -- a canonical string (and its SHA-256 digest)
   from which the client random, session id and GREASE placeholders are
   excluded, so two handshakes that differ only in their random values get
   the same fingerprint.
3. **Ambiguity/anomaly reasons** -- a traceable, machine-readable list of
   every deviation found.  A message with a hard anomaly is never reported
   with a clean status; the fingerprint is either withheld or explicitly
   flagged so it cannot be mistaken for a normal-client fingerprint.

Scope and non-goals
--------------------

* Input is limited to one complete ClientHello *handshake* message
  (``content_type == handshake``, ``HandshakeType.client_hello``), i.e. the
  four-byte handshake header followed by the whole ClientHello body.  TLS
  record framing and reassembly of a handshake message that spans several
  TLS records are intentionally out of scope; pass a :class:`~dpkt.ssl.TLSRecord`
  or record-layer bytes and a :class:`ValueError` is raised.
* SSLv2 ClientHello is out of scope.
* The module never raises on a malformed *body*.  Truncated or inconsistent
  vectors are captured as anomalies and, when the core fields can no longer
  be read reliably, the fingerprint is withheld rather than guessed.

Ordering modes
--------------

``ORDER_PRESERVED`` (the default) keeps cipher-suite and extension order,
which is itself a strong discriminant.  ``ORDER_INSENSITIVE`` must be opted
into explicitly; it sorts the ordered lists before hashing.  Two distinct
clients whose only difference is list ordering then *collide* on the
order-insensitive fingerprint.  That collision is a deliberate information
loss, not an equality claim, and every result built in that mode carries a
note saying so.  Duplicate/conflict anomalies are always computed on the raw
wire data and survive either mode.
"""
from __future__ import absolute_import

import binascii
import hashlib
import struct

from . import ssl
from . import ssl_ciphersuites

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

#: Keep cipher-suite / extension order (default; recommended).
ORDER_PRESERVED = 'order_preserved'

#: Explicit opt-in mode that sorts ordered lists; see module docstring for
#: the collision semantics.
ORDER_INSENSITIVE = 'order_insensitive'

#: HandshakeType.client_hello (RFC 5246 #7.4).
HANDSHAKE_TYPE_CLIENT_HELLO = 1

#: extension type server_name (RFC 6066).
EXT_SERVER_NAME = 0x0000
#: extension type supported_groups (RFC 7919 / RFC 4492).
EXT_SUPPORTED_GROUPS = 0x000a
#: extension type ec_point_formats (RFC 4492).
EXT_EC_POINT_FORMATS = 0x000b
#: extension type signature_algorithms (RFC 5246).
EXT_SIGNATURE_ALGORITHMS = 0x000d
#: extension type supported_versions (RFC 8446).
EXT_SUPPORTED_VERSIONS = 0x002b
#: extension type key_share (RFC 8446).
EXT_KEY_SHARE = 0x0033

# Human-readable names for the extensions we inspect.  Unknown extension
# types stay numeric rather than being forced into a name.
EXTENSION_NAMES = {
    EXT_SERVER_NAME: 'server_name',
    EXT_SUPPORTED_GROUPS: 'supported_groups',
    EXT_EC_POINT_FORMATS: 'ec_point_formats',
    EXT_SIGNATURE_ALGORITHMS: 'signature_algorithms',
    EXT_SUPPORTED_VERSIONS: 'supported_versions',
    EXT_KEY_SHARE: 'key_share',
}

# Result statuses
STATUS_OK = 'ok'
#: Parsed completely, but at least one hard protocol anomaly was found.
STATUS_ANOMALOUS = 'anomalous'
#: Core fields could not be read reliably; no fingerprint is produced.
STATUS_INVALID = 'invalid'

# Anomaly / ambiguity / observation codes.  Anomalies are hard protocol
# violations; ambiguities are legal-but-unidentifiable values; observations
# are worth recording without affecting trust in the fingerprint.
A_TRUNCATED_VECTOR = 'truncated_vector'
A_MALFORMED_VECTOR = 'malformed_vector'
A_DUPLICATE_EXTENSION = 'duplicate_extension'
A_EXTENSION_CONFLICT = 'extension_conflict'
A_DUPLICATE_SNI = 'duplicate_sni'
A_TRAILING_DATA = 'trailing_data'
A_EMPTY_CIPHER_SUITES = 'empty_cipher_suites'

AMB_UNKNOWN_CIPHER_SUITE = 'unknown_cipher_suite'

OBS_EMPTY_EXTENSION = 'empty_extension'
OBS_GREASE = 'grease_value'
OBS_SNI_CONTROL_CHARS = 'sni_control_characters'
OBS_UNKNOWN_NAME_TYPE = 'sni_unknown_name_type'

# A truncation/malformation is only fatal when it corrupts a top-level vector
# that the canonical fingerprint is built from.  A defect *inside* an
# extension payload is still a hard anomaly, but the outer cipher-suite and
# extension-type sequences remain intact and hashable, so the fingerprint is
# kept (and flagged anomalous) rather than withheld.
def _is_fatal(anomaly):
    code = anomaly['code']
    if code == A_EMPTY_CIPHER_SUITES:
        return True
    if code not in (A_TRUNCATED_VECTOR, A_MALFORMED_VECTOR):
        return False
    # Any location that is not nested inside an extension is a top-level
    # ClientHello vector (e.g. client_hello.cipher_suites, extensions block).
    return anomaly['location'].startswith('extensions[') is False


def is_grease(value):
    """Return ``True`` for a RFC 8701 GREASE code.

    GREASE values have the low nibble of each byte equal to ``0xa`` and both
    high nibbles identical (``0x?a0x?a``).  They are randomized per
    connection and therefore must never participate in a stable
    fingerprint, but they are *not* anomalies: their presence is recorded as
    an observation with the wire position where each one occurred.
    """
    if not isinstance(value, int) or not 0 <= value <= 0xffff:
        return False
    return (value & 0x0f0f) == 0x0a0a and ((value >> 8) & 0xf0) == (value & 0xf0)


def _hex16(value):
    return '%04x' % (value & 0xffff)


def _byte_ints(raw):
    # Indexing a bytearray yields an int on both Python 2 and 3, whereas
    # dpkt.compat.compat_ord is an identity function on Python 3 and would
    # leave us holding a one-byte bytes object.
    return [b for b in bytearray(raw)]


def _safe_text(raw):
    """Decode a DNS name for display without letting control chars hide data.

    The raw bytes are kept alongside the display string so length boundaries
    stay auditable.  Non-printable / control characters (including NUL, CR,
    LF, backspace and the escape character) are rendered as ``\\xHH``
    instead of being emitted literally, which otherwise lets a crafted name
    forge or erase terminal output.
    """
    out = []
    for byte in bytearray(raw):
        if byte == 0x09 or 0x20 <= byte <= 0x7e:
            out.append(chr(byte))
        else:
            out.append('\\x%02x' % byte)
    return ''.join(out)


def _anomaly(code, location, detail):
    return {'code': code, 'location': location, 'detail': detail}


class _Cursor(object):
    """Bounds-checked reader for the ClientHello body.

    Every read is checked against the declared end of its vector, so a
    truncated or inconsistent length never causes us to silently read
    neighboring fields the way a bare ``struct.unpack`` on a slice would.
    """

    def __init__(self, buf, base=0, end=None, anomalies=None, location='client_hello'):
        self.buf = buf
        self.pos = base
        self.end = len(buf) if end is None else end
        self.anomalies = anomalies if anomalies is not None else []
        self.location = location

    def remaining(self):
        return self.end - self.pos

    def read_fixed(self, size, field):
        if self.pos + size > self.end:
            self.anomalies.append(_anomaly(
                A_TRUNCATED_VECTOR, self.location + '.' + field,
                'need %d bytes at offset %d, only %d remain'
                % (size, self.pos, self.end - self.pos)))
            self.pos = self.end
            return b''
        chunk = self.buf[self.pos:self.pos + size]
        self.pos += size
        return chunk

    def read_vector(self, len_size, field):
        """Read a length-prefixed vector; returns ``(data, ok)``.

        Two distinct failures are reported separately:

        * the length prefix itself is missing
          (:data:`A_MALFORMED_VECTOR`), meaning the surrounding structure is
          not the vector it claims to be;
        * a complete prefix declares more bytes than the enclosing vector
          holds (:data:`A_TRUNCATED_VECTOR`).

        In either case ``ok`` is False and the bytes that *are* available are
        returned so downstream feature extraction stays best-effort, while the
        anomaly already on the list forces an invalid result.
        """
        if self.remaining() < len_size:
            self.anomalies.append(_anomaly(
                A_MALFORMED_VECTOR, self.location + '.' + field,
                'need a %d-byte length prefix at offset %d, only %d byte(s) remain'
                % (len_size, self.pos, self.remaining())))
            self.pos = self.end
            return b'', False
        raw_len = self.read_fixed(len_size, field + '.length')
        declared = struct.unpack('!I', (b'\x00' * (4 - len_size)) + raw_len)[0]
        start = self.pos
        stop = start + declared
        if stop > self.end:
            self.anomalies.append(_anomaly(
                A_TRUNCATED_VECTOR, self.location + '.' + field,
                'declared length %d at offset %d exceeds %d available bytes'
                % (declared, start, self.end - start)))
            data = self.buf[start:self.end]
            self.pos = self.end
            return data, False
        data = self.buf[start:stop]
        self.pos = stop
        return data, True


def _parse_sni(ext_data, anomalies, observations, index):
    """Parse the server_name extension body, preserving length boundaries."""
    result = {'names': []}
    cur = _Cursor(ext_data, anomalies=anomalies,
                  location='extensions[%d].server_name' % index)
    list_bytes, ok = cur.read_vector(2, 'server_name_list')
    if not ok:
        result['truncated'] = True
        return result
    inner = _Cursor(list_bytes, anomalies=anomalies,
                    location='extensions[%d].server_name' % index)
    while inner.remaining():
        name_type = inner.read_fixed(1, 'name_type')
        if not name_type:
            result['truncated'] = True
            return result
        name_type = _byte_ints(name_type)[0]
        host, host_ok = inner.read_vector(2, 'host_name')
        if not host_ok:
            result['truncated'] = True
            return result
        actual = len(host)
        entry = {
            'name_type': name_type,
            'declared_length': actual,
            'raw_hex': binascii.b2a_hex(host).decode('ascii'),
        }
        if name_type == 0:
            display = _safe_text(host)
            entry['display'] = display
            if any((byte < 0x20 or byte == 0x7f) for byte in _byte_ints(host)):
                observations.append({
                    'code': OBS_SNI_CONTROL_CHARS,
                    'location': 'extensions[%d].server_name' % index,
                    'detail': 'host_name of %d byte(s) contains control characters' % actual,
                })
        else:
            entry['display'] = None
            observations.append({
                'code': OBS_UNKNOWN_NAME_TYPE,
                'location': 'extensions[%d].server_name' % index,
                'detail': 'name_type %d is not host_name (0)' % name_type,
            })
        result['names'].append(entry)
    return result


def _parse_supported_groups(ext_data, anomalies, observations, index):
    cur = _Cursor(ext_data, anomalies=anomalies,
                  location='extensions[%d].supported_groups' % index)
    list_bytes, ok = cur.read_vector(2, 'named_curve_list')
    groups = []
    if not ok:
        return groups, True
    if len(list_bytes) % 2:
        anomalies.append(_anomaly(
            A_MALFORMED_VECTOR,
            'extensions[%d].supported_groups' % index,
            'named_curve_list length %d is not a multiple of 2' % len(list_bytes)))
        return groups, True
    for offset in range(0, len(list_bytes), 2):
        group = struct.unpack('!H', list_bytes[offset:offset + 2])[0]
        groups.append(group)
        if is_grease(group):
            observations.append({
                'code': OBS_GREASE,
                'location': 'extensions[%d].supported_groups[%d]' % (index, offset // 2),
                'detail': 'GREASE group 0x%04x' % group,
            })
    return groups, False


def _parse_supported_versions(ext_data, anomalies, index):
    versions = []
    cur = _Cursor(ext_data, anomalies=anomalies,
                  location='extensions[%d].supported_versions' % index)
    list_bytes, ok = cur.read_vector(1, 'supported_versions_list')
    if not ok:
        return versions, True
    if len(list_bytes) % 2:
        anomalies.append(_anomaly(
            A_MALFORMED_VECTOR,
            'extensions[%d].supported_versions' % index,
            'version list length %d is not a multiple of 2' % len(list_bytes)))
        return versions, True
    for offset in range(0, len(list_bytes), 2):
        versions.append(struct.unpack('!H', list_bytes[offset:offset + 2])[0])
    return versions, False


def _parse_signature_algorithms(ext_data, anomalies, index):
    cur = _Cursor(ext_data, anomalies=anomalies,
                  location='extensions[%d].signature_algorithms' % index)
    list_bytes, ok = cur.read_vector(2, 'supported_signature_algorithms')
    algos = []
    if not ok:
        return algos, True
    if len(list_bytes) % 2:
        anomalies.append(_anomaly(
            A_MALFORMED_VECTOR,
            'extensions[%d].signature_algorithms' % index,
            'algorithm list length %d is not a multiple of 2' % len(list_bytes)))
        return algos, True
    for offset in range(0, len(list_bytes), 2):
        algos.append(struct.unpack('!H', list_bytes[offset:offset + 2])[0])
    return algos, False


def _parse_key_share(ext_data, anomalies, observations, index):
    """Parse key_share entries (ClientHello variant, RFC 8446 #4.2.8)."""
    cur = _Cursor(ext_data, anomalies=anomalies,
                  location='extensions[%d].key_share' % index)
    list_bytes, ok = cur.read_vector(2, 'client_shares')
    entries = []
    if not ok:
        return entries, True
    inner = _Cursor(list_bytes, anomalies=anomalies,
                    location='extensions[%d].key_share' % index)
    entry_index = 0
    while inner.remaining():
        group_raw = inner.read_fixed(2, 'named_group')
        if not group_raw:
            return entries, True
        group = struct.unpack('!H', group_raw)[0]
        key_ex, key_ok = inner.read_vector(2, 'key_exchange')
        if not key_ok:
            return entries, True
        entries.append({'group': group, 'key_exchange_length': len(key_ex)})
        if is_grease(group):
            observations.append({
                'code': OBS_GREASE,
                'location': 'extensions[%d].key_share[%d]' % (index, entry_index),
                'detail': 'GREASE group 0x%04x' % group,
            })
        entry_index += 1
    return entries, False


def _parse_ec_point_formats(ext_data, anomalies, index):
    cur = _Cursor(ext_data, anomalies=anomalies,
                  location='extensions[%d].ec_point_formats' % index)
    list_bytes, ok = cur.read_vector(1, 'ec_point_format_list')
    if not ok:
        return [], True
    return _byte_ints(list_bytes), False


def _strict_parse_client_hello(body):
    """Parse a ClientHello body with explicit bounds and anomaly capture."""
    anomalies = []
    ambiguities = []
    observations = []

    cur = _Cursor(body, anomalies=anomalies)
    version_raw = cur.read_fixed(2, 'client_version')
    # Consume the 32-byte client random purely to keep offsets correct.  It is
    # deliberately not bound to a name and never copied into any feature or
    # fingerprint structure, so two handshakes differing only in random values
    # cannot be distinguished through the result of this module.
    cur.read_fixed(32, 'random')
    session_id, _ = cur.read_vector(1, 'session_id')

    cipher_bytes, cipher_ok = cur.read_vector(2, 'cipher_suites')
    cipher_suites = []
    if len(cipher_bytes) % 2:
        anomalies.append(_anomaly(
            A_MALFORMED_VECTOR, 'cipher_suites',
            'cipher_suites length %d is not a multiple of 2' % len(cipher_bytes)))
    for offset in range(0, len(cipher_bytes) - 1, 2):
        code = struct.unpack('!H', cipher_bytes[offset:offset + 2])[0]
        entry = {'code': _hex16(code), 'index': offset // 2}
        if is_grease(code):
            entry['grease'] = True
            entry['known'] = True
            observations.append({
                'code': OBS_GREASE,
                'location': 'cipher_suites[%d]' % (offset // 2),
                'detail': 'GREASE cipher suite 0x%04x' % code,
            })
        elif code in ssl_ciphersuites.BY_CODE:
            entry['known'] = True
            entry['name'] = ssl_ciphersuites.BY_CODE[code].name
        else:
            entry['known'] = False
            entry['name'] = None
            ambiguities.append({
                'code': AMB_UNKNOWN_CIPHER_SUITE,
                'location': 'cipher_suites[%d]' % (offset // 2),
                'detail': 'cipher suite 0x%04x is not in the local registry and '
                          'is not a RFC 8701 GREASE value; its numeric code is '
                          'retained verbatim' % code,
            })
        cipher_suites.append(entry)
    if cipher_ok and not cipher_suites:
        anomalies.append(_anomaly(
            A_EMPTY_CIPHER_SUITES, 'cipher_suites',
            'cipher_suites vector is present but empty'))

    comp_bytes, _ = cur.read_vector(1, 'compression_methods')
    compression_methods = _byte_ints(comp_bytes)
    compression_hex = ['%02x' % method for method in compression_methods]

    raw_extensions = []
    if cur.remaining():
        # At least four bytes (2-byte block length + one extension's type and
        # data length) are required for any real extensions block.  Fewer
        # bytes mean trailing garbage rather than a truncated extension, so
        # leave them for the trailing-data check below.
        if cur.remaining() < 4:
            anomalies.append(_anomaly(
                A_TRAILING_DATA, 'client_hello',
                '%d trailing byte(s) cannot form an extensions block'
                % cur.remaining()))
            cur.pos = cur.end
        else:
            ext_block, _ = cur.read_vector(2, 'extensions')
            ext_cursor = _Cursor(ext_block, anomalies=anomalies,
                                 location='extensions')
            while ext_cursor.remaining():
                # A lone final byte cannot hold a 2-byte extension type: the
                # declared extensions block itself is then internally truncated.
                if ext_cursor.remaining() < 2:
                    anomalies.append(_anomaly(
                        A_TRUNCATED_VECTOR, 'extensions',
                        '%d dangling byte(s) cannot hold an extension type'
                        % ext_cursor.remaining()))
                    ext_cursor.pos = ext_cursor.end
                    break
                type_raw = ext_cursor.read_fixed(2, 'extension_type')
                ext_type = struct.unpack('!H', type_raw)[0]
                if ext_cursor.remaining() < 2:
                    anomalies.append(_anomaly(
                        A_TRUNCATED_VECTOR, 'extensions',
                        'extension 0x%04x has no extension_data length field'
                        % ext_type))
                    ext_cursor.pos = ext_cursor.end
                    break
                ext_data, data_ok = ext_cursor.read_vector(2, 'extension_data')
                if not data_ok:
                    break
                index = len(raw_extensions)
                entry = {
                    'index': index,
                    'type': _hex16(ext_type),
                    'name': EXTENSION_NAMES.get(ext_type, 'unknown'),
                    'data_length': len(ext_data),
                    'data_hex': binascii.b2a_hex(ext_data).decode('ascii'),
                    'empty': len(ext_data) == 0,
                }
                if entry['empty']:
                    observations.append({
                        'code': OBS_EMPTY_EXTENSION,
                        'location': 'extensions[%d]' % index,
                        'detail': 'extension 0x%04x has an empty extension_data' % ext_type,
                    })
                if is_grease(ext_type):
                    entry['grease'] = True
                    observations.append({
                        'code': OBS_GREASE,
                        'location': 'extensions[%d]' % index,
                        'detail': 'GREASE extension type 0x%04x' % ext_type,
                    })
                raw_extensions.append(entry)
    if cur.remaining():
        anomalies.append(_anomaly(
            A_TRAILING_DATA, 'client_hello',
            '%d byte(s) remain after the declared ClientHello vectors'
            % cur.remaining()))

    # Duplicate / conflicting extension detection on the raw, ordered data.
    seen_types = {}
    for entry in raw_extensions:
        ext_type = entry['type']
        index = entry['index']
        if ext_type in seen_types:
            first_index = seen_types[ext_type]
            first_entry = raw_extensions[first_index]
            duplicate_code = (A_DUPLICATE_SNI if int(ext_type, 16) == EXT_SERVER_NAME
                              else A_DUPLICATE_EXTENSION)
            anomalies.append(_anomaly(
                duplicate_code, 'extensions[%d]' % index,
                'extension 0x%s already appeared at index %d'
                % (ext_type, first_index)))
            if first_entry['data_hex'] != entry['data_hex']:
                anomalies.append(_anomaly(
                    A_EXTENSION_CONFLICT, 'extensions[%d]' % index,
                    'extension 0x%s at index %d carries different data than index %d'
                    % (ext_type, index, first_index)))
        else:
            seen_types[ext_type] = index

    # Best-effort structured parsing of well-known extension payloads.
    sni = None
    for entry in raw_extensions:
        ext_type = int(entry['type'], 16)
        ext_data = binascii.a2b_hex(entry['data_hex'])
        index = entry['index']
        if ext_type == EXT_SERVER_NAME:
            parsed = _parse_sni(ext_data, anomalies, observations, index)
            if sni is None:
                sni = parsed
            else:
                # keep every SNI payload traceable; never silently overwrite
                sni.setdefault('duplicate_payloads', []).append(parsed)
            entry['parsed'] = parsed
        elif ext_type == EXT_SUPPORTED_GROUPS:
            groups, _ = _parse_supported_groups(ext_data, anomalies, observations, index)
            entry['parsed'] = {'groups': [_hex16(g) for g in groups]}
        elif ext_type == EXT_SUPPORTED_VERSIONS:
            versions, _ = _parse_supported_versions(ext_data, anomalies, index)
            entry['parsed'] = {'versions': [_hex16(v) for v in versions]}
        elif ext_type == EXT_SIGNATURE_ALGORITHMS:
            algos, _ = _parse_signature_algorithms(ext_data, anomalies, index)
            entry['parsed'] = {'algorithms': [_hex16(a) for a in algos]}
        elif ext_type == EXT_KEY_SHARE:
            shares, _ = _parse_key_share(ext_data, anomalies, observations, index)
            entry['parsed'] = {'client_shares': shares}
        elif ext_type == EXT_EC_POINT_FORMATS:
            formats, _ = _parse_ec_point_formats(ext_data, anomalies, index)
            entry['parsed'] = {'formats': formats}

    feature = {
        'client_version': _hex16(struct.unpack('!H', version_raw)[0]) if version_raw else None,
        'session_id_length': len(session_id),
        'cipher_suites': cipher_suites,
        'compression_methods': compression_hex,
        'extensions': raw_extensions,
        'sni': sni,
    }
    return feature, anomalies, ambiguities, observations


def _build_canonical(feature, order_mode):
    """Build the JA3-style canonical string and the ordered raw codes."""
    cipher_codes = [c['code'] for c in feature['cipher_suites'] if not c.get('grease')]
    ext_codes = [e['type'] for e in feature['extensions'] if not e.get('grease')]
    compression = feature['compression_methods']

    if order_mode == ORDER_INSENSITIVE:
        cipher_codes = sorted(cipher_codes)
        ext_codes = sorted(ext_codes)
        compression = sorted(compression)

    parts = [
        feature['client_version'] or '',
        '-'.join(cipher_codes),
        '-'.join(compression),
        '-'.join(ext_codes),
    ]
    canonical = '|'.join(parts)
    ordered = {
        'cipher_suites': [c['code'] for c in feature['cipher_suites']],
        'extension_types': [e['type'] for e in feature['extensions']],
        'compression_methods': list(feature['compression_methods']),
    }
    return canonical, ordered


def fingerprint_client_hello(buf, order_mode=ORDER_PRESERVED):
    """Extract raw features, a stable fingerprint and anomaly reasons.

    Args:
        buf: a complete ClientHello handshake message.  Accepted forms are
            raw handshake bytes (``01 00 .. ..``), a
            :class:`~dpkt.ssl.TLSHandshake` or a
            :class:`~dpkt.ssl.TLSClientHello` object produced by dpkt.
        order_mode: :data:`ORDER_PRESERVED` (default) or
            :data:`ORDER_INSENSITIVE`.  The latter is an explicit opt-in;
            see the module docstring for its collision semantics.

    Returns:
        dict with keys:

        * ``status`` -- :data:`STATUS_OK`, :data:`STATUS_ANOMALOUS` or
          :data:`STATUS_INVALID`.
        * ``order_mode`` -- the mode actually used.
        * ``raw_features`` -- ordered, unnormalized wire features (no random).
        * ``fingerprint`` -- SHA-256 hex digest, or ``None`` when invalid.
        * ``canonical`` -- the canonical string that was hashed, or ``None``.
        * ``anomalies`` / ``ambiguities`` / ``observations`` -- traceable
          lists with ``code``, ``location`` and ``detail`` on each entry.
        * ``collision_notes`` -- present only in order-insensitive mode.

    Raises:
        ValueError: if ``order_mode`` is unknown, the input is not a
            ClientHello handshake message (including record-layer input,
            since reassembly is out of scope), or the outer handshake framing
            is itself truncated.
    """
    if order_mode not in (ORDER_PRESERVED, ORDER_INSENSITIVE):
        raise ValueError('unknown order_mode %r; use ORDER_PRESERVED or '
                         'ORDER_INSENSITIVE' % (order_mode,))

    body, source = _extract_client_hello_body(buf)
    feature, anomalies, ambiguities, observations = _strict_parse_client_hello(body)

    hard_invalid = any(_is_fatal(item) for item in anomalies)
    if hard_invalid:
        # A core, fingerprint-bearing vector is unreadable, so emitting a
        # hash would mean silently guessing.  Withhold the fingerprint and
        # keep the partial raw features plus every reason for the failure.
        status = STATUS_INVALID
        canonical = None
        digest = None
    else:
        canonical, ordered = _build_canonical(feature, order_mode)
        feature['ordered_codes'] = ordered
        digest = hashlib.sha256(canonical.encode('ascii')).hexdigest()
        # Extension-internal defects, duplicates, conflicts and trailing data
        # still disqualify the message from a clean status even though the
        # outer sequences are intact.
        status = STATUS_ANOMALOUS if anomalies else STATUS_OK

    result = {
        'status': status,
        'order_mode': order_mode,
        'input_source': source,
        'raw_features': feature,
        'fingerprint': digest,
        'canonical': canonical,
        'anomalies': anomalies,
        'ambiguities': ambiguities,
        'observations': observations,
    }
    if order_mode == ORDER_INSENSITIVE:
        result['collision_notes'] = [
            'order_insensitive mode sorts cipher-suite, compression and '
            'extension-type lists before hashing; messages whose only '
            'difference is list ordering collide on fingerprint even though '
            'their raw_features remain distinct',
            'duplicate and conflicting extensions are still reported from '
            'the raw wire order and are not merged by this mode',
        ]
    return result


def _extract_client_hello_body(buf):
    """Validate outer handshake framing and return the ClientHello body.

    Only the four-byte handshake header (``HandshakeType`` + 24-bit length)
    is validated here.  We deliberately do *not* run dpkt's
    :class:`~dpkt.ssl.TLSClientHello` unpacker on raw input: dpkt's variable
    vector parser raises :class:`~dpkt.dpkt.UnpackError` on a truncated body,
    which would defeat this module's purpose of capturing truncated vectors
    as traceable anomalies instead of aborting.  The strict, bounds-checked
    parser in :func:`_strict_parse_client_hello` handles the body instead.
    """
    if isinstance(buf, ssl.TLSRecord):
        raise ValueError(
            'TLSRecord input is out of scope: supply the reassembled '
            'ClientHello handshake message (record reassembly is not handled)')
    if isinstance(buf, ssl.TLSHandshake):
        if buf.type != HANDSHAKE_TYPE_CLIENT_HELLO:
            raise ValueError(
                'expected handshake type ClientHello (1), got %d' % buf.type)
        # Re-serialize what dpkt accepted; the declared length already matched
        # when this object was constructed.
        return bytes(buf)[4:], 'dpkt.TLSHandshake'
    if isinstance(buf, ssl.TLSClientHello):
        return bytes(buf), 'dpkt.TLSClientHello'
    if not isinstance(buf, (bytes, bytearray)):
        raise ValueError('expected bytes or a dpkt TLS handshake object, got %s'
                         % type(buf).__name__)
    buf = bytes(buf)
    if not buf:
        raise ValueError('empty input')
    first = _byte_ints(buf[:1])[0]
    # A TLS record starts with a content type (20..23); a handshake message
    # starts with the handshake type (1).
    if first in ssl.RECORD_TYPES:
        raise ValueError(
            'input looks like a TLS record layer (content_type=%d); record '
            'reassembly is out of scope, pass the complete ClientHello '
            'handshake message instead' % first)
    if len(buf) < 4:
        raise ValueError(
            'truncated handshake framing: need a 4-byte handshake header, '
            'got %d byte(s)' % len(buf))
    if first != HANDSHAKE_TYPE_CLIENT_HELLO:
        raise ValueError(
            'expected handshake type ClientHello (1), got %d' % first)
    declared_length = struct.unpack('!I', b'\x00' + buf[1:4])[0]
    body = buf[4:]
    if len(body) != declared_length:
        raise ValueError(
            'truncated handshake framing: body declares %d byte(s) but %d '
            'are present; complete handshake messages only are in scope'
            % (declared_length, len(body)))
    return body, 'handshake_bytes'


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def _vec(len_size, data):
    return len(data).to_bytes(len_size, 'big') + data


def _ext(ext_type, data=b''):
    return struct.pack('!HH', ext_type, len(data)) + data


def _sni_ext(names):
    body = b''.join(struct.pack('!BH', name_type, len(host)) + host
                    for name_type, host in names)
    return _ext(EXT_SERVER_NAME, _vec(2, body))


def _client_hello_body(version=0x0303, random=b'R' * 32, session_id=b'',
                       ciphers=(0x1301, 0x1302), comps=(0,), extensions=b''):
    body = struct.pack('!H', version) + random + _vec(1, session_id)
    body += _vec(2, b''.join(struct.pack('!H', code) for code in ciphers))
    body += _vec(1, bytes(comps))
    if extensions:
        body += _vec(2, extensions)
    return body


def _handshake(body):
    return b'\x01' + len(body).to_bytes(3, 'big') + body


class TestTLSFingerprint(object):
    """Behavioral coverage for anomaly-preserving ClientHello fingerprinting."""

    def test_grease_classifier_boundaries(self):
        for value in (0x0a0a, 0x1a1a, 0x7a7a, 0xfafa):
            assert is_grease(value) is True
        # Same low nibbles but mismatched high nibbles are not GREASE.
        for value in (0x002f, 0x1301, 0x0b0a, 0x1a1b, 0xffff, 0):
            assert is_grease(value) is False
        assert is_grease(0x1a1a0001) is False

    def test_random_only_difference_collides(self):
        first = _handshake(_client_hello_body(
            random=b'A' * 32, extensions=_sni_ext([(0, b'example.com')])))
        second = _handshake(_client_hello_body(
            random=b'B' * 32, extensions=_sni_ext([(0, b'example.com')])))
        result_a = fingerprint_client_hello(first)
        result_b = fingerprint_client_hello(second)
        assert result_a['status'] == STATUS_OK
        assert result_a['fingerprint'] == result_b['fingerprint']
        assert result_a['canonical'] == result_b['canonical']

    def test_client_random_never_leaks(self):
        # The random value must not appear anywhere in the returned structure.
        message = _handshake(_client_hello_body(random=b'Z' * 32))
        result = fingerprint_client_hello(message)
        assert b'ZZZZ' not in repr(result).encode('ascii')
        assert 'random' not in result['raw_features']

    def test_grease_is_filtered_from_fingerprint_but_recorded(self):
        first = _handshake(_client_hello_body(
            ciphers=(0x0a0a, 0x1301), extensions=_ext(0x0a0a) + _ext(0x0011)))
        second = _handshake(_client_hello_body(
            ciphers=(0x4a4a, 0x1301), extensions=_ext(0x4a4a) + _ext(0x0011)))
        result_a = fingerprint_client_hello(first)
        result_b = fingerprint_client_hello(second)
        # Different randomized GREASE picks must not split the fingerprint.
        assert result_a['fingerprint'] == result_b['fingerprint']
        assert '0a0a' not in result_a['canonical']
        # The raw ordered features still expose the GREASE positions.
        assert result_a['raw_features']['cipher_suites'][0].get('grease') is True
        grease = [o for o in result_a['observations'] if o['code'] == OBS_GREASE]
        assert {o['location'] for o in grease} == {'cipher_suites[0]', 'extensions[0]'}
        # GREASE is not an anomaly.
        assert result_a['status'] == STATUS_OK
        # A reserved GREASE value must not also be called an unknown suite.
        assert result_a['ambiguities'] == []

    def test_unknown_cipher_suite_is_ambiguous_but_stable(self):
        message = _handshake(_client_hello_body(ciphers=(0x1301, 0x9999)))
        result = fingerprint_client_hello(message)
        assert result['status'] == STATUS_OK
        ambiguity = result['ambiguities']
        assert len(ambiguity) == 1
        assert ambiguity[0]['code'] == AMB_UNKNOWN_CIPHER_SUITE
        assert ambiguity[0]['location'] == 'cipher_suites[1]'
        # Numeric code is retained verbatim and deterministically hashed.
        entry = result['raw_features']['cipher_suites'][1]
        assert entry['known'] is False and entry['code'] == '9999'
        assert '9999' in result['canonical']
        assert result['fingerprint'] == fingerprint_client_hello(message)['fingerprint']

    def test_duplicate_sni_conflict_is_anomalous_and_traceable(self):
        message = _handshake(_client_hello_body(extensions=(
            _sni_ext([(0, b'a.example')]) + _sni_ext([(0, b'b.example')]))))
        result = fingerprint_client_hello(message)
        codes = [a['code'] for a in result['anomalies']]
        assert A_DUPLICATE_SNI in codes and A_EXTENSION_CONFLICT in codes
        assert result['status'] == STATUS_ANOMALOUS
        # It must not be disguised as a normal fingerprint.
        conflict = next(a for a in result['anomalies']
                        if a['code'] == A_EXTENSION_CONFLICT)
        assert conflict['location'] == 'extensions[1]'
        # Both SNI payloads stay reachable.
        assert len(result['raw_features']['sni']['duplicate_payloads']) == 1

    def test_duplicate_identical_extension_is_duplicate_without_conflict(self):
        message = _handshake(_client_hello_body(
            extensions=_ext(0x0011, b'\x00\x01') + _ext(0x0011, b'\x00\x01')))
        result = fingerprint_client_hello(message)
        codes = [a['code'] for a in result['anomalies']]
        assert codes == [A_DUPLICATE_EXTENSION]
        assert A_EXTENSION_CONFLICT not in codes
        assert result['status'] == STATUS_ANOMALOUS

    def test_duplicate_extension_with_divergent_data_conflicts(self):
        message = _handshake(_client_hello_body(
            extensions=_ext(0x0011, b'\x00\x01') + _ext(0x0011, b'\x00\x02')))
        result = fingerprint_client_hello(message)
        codes = {a['code'] for a in result['anomalies']}
        assert A_DUPLICATE_EXTENSION in codes and A_EXTENSION_CONFLICT in codes

    def test_empty_extension_is_observation_only(self):
        message = _handshake(_client_hello_body(extensions=_ext(0x0010)))
        result = fingerprint_client_hello(message)
        assert result['status'] == STATUS_OK
        assert result['anomalies'] == []
        observation = result['observations'][0]
        assert observation['code'] == OBS_EMPTY_EXTENSION
        assert result['raw_features']['extensions'][0]['empty'] is True

    def test_sni_reports_length_and_escapes_control_characters(self):
        host = b'evil\x00.example'
        message = _handshake(_client_hello_body(extensions=_sni_ext([(0, host)])))
        result = fingerprint_client_hello(message)
        name = result['raw_features']['sni']['names'][0]
        assert name['declared_length'] == len(host)
        assert name['raw_hex'] == binascii.b2a_hex(host).decode('ascii')
        # NUL is rendered as an escape rather than emitted as a raw byte.
        assert name['display'] == 'evil\\x00.example'
        control = [o for o in result['observations']
                   if o['code'] == OBS_SNI_CONTROL_CHARS]
        assert len(control) == 1

    def test_inner_truncated_vector_is_invalid_without_fingerprint(self):
        # Outer frame is complete, but the cipher vector declares 64 bytes
        # while only one is present.
        body = (struct.pack('!H', 0x0303) + b'R' * 32 + b'\x00'
                + struct.pack('!H', 0x0040) + b'\x00\x2f')
        result = fingerprint_client_hello(_handshake(body))
        assert result['status'] == STATUS_INVALID
        assert result['fingerprint'] is None and result['canonical'] is None
        assert A_TRUNCATED_VECTOR in [a['code'] for a in result['anomalies']]

    def test_outer_truncation_raises_value_error(self):
        message = _handshake(_client_hello_body())[:-3]
        try:
            fingerprint_client_hello(message)
        except ValueError:
            return
        raise AssertionError('truncated outer framing must raise ValueError')

    def test_malformed_odd_cipher_vector_is_invalid(self):
        body = (struct.pack('!H', 0x0303) + b'R' * 32 + b'\x00'
                + struct.pack('!H', 3) + b'\x00\x2f\x13' + b'\x01\x00')
        result = fingerprint_client_hello(_handshake(body))
        assert result['status'] == STATUS_INVALID
        assert A_MALFORMED_VECTOR in [a['code'] for a in result['anomalies']]

    def test_extension_internal_defect_keeps_fingerprint_but_flags_anomaly(self):
        # The outer extension TLV is intact; only the SNI inner vector lies
        # about its length.  The extension-type sequence is still hashable.
        sni_bad = _ext(EXT_SERVER_NAME, _vec(2, b'\x00\x00\x00\x05ab'))
        body = (struct.pack('!H', 0x0303) + b'R' * 32 + _vec(1, b'')
                + _vec(2, struct.pack('!H', 0x1301)) + _vec(1, b'\x00')
                + _vec(2, sni_bad))
        result = fingerprint_client_hello(_handshake(body))
        assert result['status'] == STATUS_ANOMALOUS
        assert result['anomalies'][0]['location'].startswith('extensions[0]')
        assert result['fingerprint'] is not None

    def test_extensions_block_skeleton_truncation_is_invalid(self):
        # A dangling fragment inside the declared extensions block means the
        # extension-type sequence itself cannot be trusted.
        broken_extensions = _ext(0x0010) + b'\x00\x11\x00'
        body = (struct.pack('!H', 0x0303) + b'R' * 32 + _vec(1, b'')
                + _vec(2, struct.pack('!H', 0x1301)) + _vec(1, b'\x00')
                + _vec(2, broken_extensions))
        result = fingerprint_client_hello(_handshake(body))
        assert result['status'] == STATUS_INVALID
        assert result['anomalies'][0]['location'] == 'extensions'
        assert result['fingerprint'] is None

    def test_empty_cipher_suites_is_invalid(self):
        body = (struct.pack('!H', 0x0303) + b'R' * 32 + b'\x00'
                + struct.pack('!H', 0) + b'\x01\x00')
        result = fingerprint_client_hello(_handshake(body))
        assert result['status'] == STATUS_INVALID
        assert A_EMPTY_CIPHER_SUITES in [a['code'] for a in result['anomalies']]

    def test_trailing_data_is_anomalous_but_keeps_fingerprint(self):
        body = (struct.pack('!H', 0x0303) + b'R' * 32 + _vec(1, b'')
                + _vec(2, struct.pack('!H', 0x1301)) + _vec(1, b'\x00')
                + _vec(2, _ext(0x0010)) + b'\xde\xad\xbe\xef')
        result = fingerprint_client_hello(_handshake(body))
        assert result['status'] == STATUS_ANOMALOUS
        assert [a['code'] for a in result['anomalies']] == [A_TRAILING_DATA]
        assert result['fingerprint'] is not None

    def test_default_order_preservation_distinguishes_ordering(self):
        first = _handshake(_client_hello_body(
            ciphers=(0x1301, 0x1302), extensions=_ext(0x0011) + _ext(0x0010)))
        second = _handshake(_client_hello_body(
            ciphers=(0x1302, 0x1301), extensions=_ext(0x0010) + _ext(0x0011)))
        assert (fingerprint_client_hello(first)['fingerprint']
                != fingerprint_client_hello(second)['fingerprint'])

    def test_order_insensitive_is_opt_in_and_documents_collision(self):
        first = _handshake(_client_hello_body(
            ciphers=(0x1301, 0x1302), extensions=_ext(0x0011) + _ext(0x0010)))
        second = _handshake(_client_hello_body(
            ciphers=(0x1302, 0x1301), extensions=_ext(0x0010) + _ext(0x0011)))
        result_a = fingerprint_client_hello(first, order_mode=ORDER_INSENSITIVE)
        result_b = fingerprint_client_hello(second, order_mode=ORDER_INSENSITIVE)
        assert result_a['fingerprint'] == result_b['fingerprint']
        assert result_a['order_mode'] == ORDER_INSENSITIVE
        assert result_a['collision_notes']
        # Raw features remain distinct even when the hashes collide.
        assert (result_a['raw_features']['ordered_codes']['cipher_suites']
                != result_b['raw_features']['ordered_codes']['cipher_suites'])

    def test_record_layer_input_is_rejected(self):
        message = _handshake(_client_hello_body())
        record = b'\x16\x03\x01' + len(message).to_bytes(2, 'big') + message
        try:
            fingerprint_client_hello(record)
        except ValueError:
            return
        raise AssertionError('record layer input must be rejected as out of scope')

    def test_dpkt_objects_are_accepted(self):
        message = _handshake(_client_hello_body(extensions=_ext(0x0010)))
        expected = fingerprint_client_hello(message)
        handshake = ssl.TLSHandshake(message)
        assert (fingerprint_client_hello(handshake)['fingerprint']
                == expected['fingerprint'])
        assert (fingerprint_client_hello(handshake.data)['fingerprint']
                == expected['fingerprint'])

    def test_non_client_hello_handshake_is_rejected(self):
        server_hello = b'\x02\x00\x00\x04\x03\x03' + b'\x00' * 32
        try:
            fingerprint_client_hello(server_hello)
        except ValueError:
            return
        raise AssertionError('non-ClientHello handshake must be rejected')

    def test_invalid_order_mode_raises(self):
        message = _handshake(_client_hello_body())
        try:
            fingerprint_client_hello(message, order_mode='sorted')
        except ValueError:
            return
        raise AssertionError('unknown order_mode must raise ValueError')

    def test_canonical_string_structure(self):
        message = _handshake(_client_hello_body(
            ciphers=(0x1301,), comps=(0,), extensions=_ext(0x0011)))
        result = fingerprint_client_hello(message)
        version, ciphers, comps, extensions = result['canonical'].split('|')
        assert version == '0303'
        assert ciphers == '1301'
        assert comps == '00'
        assert extensions == '0011'
        digest = hashlib.sha256(result['canonical'].encode('ascii')).hexdigest()
        assert digest == result['fingerprint']
