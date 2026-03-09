#!/usr/bin/env python3
"""
End-to-end PSBT signing tests against a real Jade device.

Test 1: Standard LTC PSBTv0 signing (P2WPKH)
Test 2: MWEB input signing via standalone RPC (sign_mweb_input)
Test 3: Pure-MWEB PSBTv2 signing via sign_psbt

Requirements:
  uvx --with cbor2 --with pyserial --with ecdsa --with blake3 --with base58 python3 test_e2e_psbt.py

If the Jade is locked, this script will request PIN entry on-device.
"""

import struct
import sys
import os
import hashlib
import hmac
import time
import argparse
import json
import urllib.error
import urllib.request

# Force unbuffered stdout so progress is visible immediately
sys.stdout.reconfigure(line_buffering=True)

import blake3 as blake3_mod
import base58
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point

sys.path.insert(0, os.path.dirname(__file__))
from jadepy import JadeAPI, JadeError


DEFAULT_SERIAL_TIMEOUT = 2.0
DEFAULT_BOOT_TIMEOUT = 30.0
DEFAULT_POLL_INTERVAL = 0.5


# ---------------------------------------------------------------------------
#  Helpers: compact-size / PSBT key-value encoding
# ---------------------------------------------------------------------------

def compact_size(n):
    if n < 0xfd:
        return bytes([n])
    elif n < 0x10000:
        return b'\xfd' + struct.pack('<H', n)
    elif n < 0x100000000:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)


def kv(key_type, key_data, value):
    """Encode a single PSBT key-value pair."""
    key = bytes([key_type]) + key_data
    return compact_size(len(key)) + key + compact_size(len(value)) + value


def separator():
    return b'\x00'


# ---------------------------------------------------------------------------
#  Helpers: Bitcoin transaction serialization
# ---------------------------------------------------------------------------

def serialize_tx(version, inputs, outputs, locktime):
    """Serialize a minimal Bitcoin transaction (no witness)."""
    tx = struct.pack('<i', version)
    tx += compact_size(len(inputs))
    for txid, vout, script_sig, sequence in inputs:
        tx += txid  # 32 bytes, internal byte order
        tx += struct.pack('<I', vout)
        tx += compact_size(len(script_sig)) + script_sig
        tx += struct.pack('<I', sequence)
    tx += compact_size(len(outputs))
    for amount, script_pubkey in outputs:
        tx += struct.pack('<q', amount)
        tx += compact_size(len(script_pubkey)) + script_pubkey
    tx += struct.pack('<I', locktime)
    return tx


def witness_utxo(amount, script_pubkey):
    """Serialize a witness UTXO (CTxOut): 8-byte LE amount + varint script."""
    return struct.pack('<q', amount) + compact_size(len(script_pubkey)) + script_pubkey


def hash160(data):
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()


def p2wpkh_script(pubkey_hash):
    """OP_0 <20-byte-hash>"""
    return b'\x00\x14' + pubkey_hash


def txid_of(raw_tx):
    return hashlib.sha256(hashlib.sha256(raw_tx).digest()).digest()


# ---------------------------------------------------------------------------
#  Helpers: BIP32 path encoding
# ---------------------------------------------------------------------------

H = 0x80000000  # hardened offset


def encode_path(path):
    return b''.join(struct.pack('<I', p) for p in path)


def bip32_derivation_kv(pubkey, fingerprint, path):
    """Input/output type 0x06: BIP32 derivation."""
    value = struct.pack('<I', fingerprint) + encode_path(path)
    return kv(0x06, pubkey, value)


def key_origin_kv(key_type, pubkey, fingerprint_bytes, path):
    """Encode a key-origin map entry using raw 4-byte fingerprint bytes."""
    return kv(key_type, pubkey, fingerprint_bytes + encode_path(path))


# ---------------------------------------------------------------------------
#  Helpers: MWEB crypto
# ---------------------------------------------------------------------------

def mweb_hashed(tag_byte, data):
    """BLAKE3(tag_byte || data) -> 32 bytes."""
    h = blake3_mod.blake3()
    h.update(bytes([tag_byte]))
    h.update(data)
    return h.digest()


_G = SECP256k1.generator
_order = SECP256k1.order
_curve = SECP256k1.curve
_p = _curve.p()


def _compress(point):
    """EC Point → 33-byte compressed pubkey."""
    prefix = b'\x02' if point.y() % 2 == 0 else b'\x03'
    return prefix + point.x().to_bytes(32, 'big')


def _decompress(pubkey_33):
    """33-byte compressed pubkey → EC Point."""
    prefix = pubkey_33[0]
    x = int.from_bytes(pubkey_33[1:], 'big')
    y_sq = (pow(x, 3, _p) + 7) % _p
    y = pow(y_sq, (_p + 1) // 4, _p)
    if (y % 2 == 0) != (prefix == 0x02):
        y = _p - y
    return Point(_curve, x, y)


def ec_pubkey(secret):
    """Compute compressed public key from 32-byte secret."""
    s = int.from_bytes(secret, 'big')
    return _compress(s * _G)


def ec_point_mul(pubkey_bytes, scalar):
    """Multiply a public key point by a scalar."""
    P = _decompress(pubkey_bytes)
    s = int.from_bytes(scalar, 'big')
    return _compress(s * P)


def ec_point_add(pubkey_a, pubkey_b):
    """Add two public key points."""
    A = _decompress(pubkey_a)
    B = _decompress(pubkey_b)
    return _compress(A + B)


def random_valid_secret():
    """Generate a random non-zero secp256k1 scalar encoded in 32 bytes."""
    while True:
        candidate = os.urandom(32)
        scalar = int.from_bytes(candidate, 'big')
        if 0 < scalar < _order:
            return candidate


def derive_mweb_stealth_components(scan_key, spend_pub, address_index):
    """Return (A_i, B_i) for an MWEB address index."""
    mi_input = struct.pack('<I', address_index) + scan_key
    m_i = mweb_hashed(ord('A'), mi_input)
    mi_pub = ec_pubkey(m_i)
    Bi = ec_point_add(spend_pub, mi_pub)
    Ai = ec_point_mul(Bi, scan_key)
    return Ai, Bi


def derive_mweb_spent_output_pubkey(scan_key, spend_pub, address_index, key_exchange_pubkey):
    """Return (shared_secret, spent_output_pubkey) for a synthetic MWEB UTXO."""
    ecdh_result = ec_point_mul(key_exchange_pubkey, scan_key)
    shared_secret = mweb_hashed(ord('D'), ecdh_result)
    out_key_hash = mweb_hashed(ord('O'), shared_secret)
    _, Bi = derive_mweb_stealth_components(scan_key, spend_pub, address_index)
    Ko = ec_point_mul(Bi, out_key_hash)
    return shared_secret, Ko


# ---------------------------------------------------------------------------
#  Helpers: BIP32 public child derivation (non-hardened only)
# ---------------------------------------------------------------------------

def bip32_derive_child_pubkey(xpub_str, *indices):
    """Derive a non-hardened child pubkey from an xpub string.
    Returns (child_pubkey_33bytes, child_chaincode_32bytes)."""
    raw = base58.b58decode_check(xpub_str)
    # xpub: 4 version + 1 depth + 4 fingerprint + 4 child_number + 32 chaincode + 33 pubkey
    chaincode = raw[13:45]
    pubkey = raw[45:78]

    for idx in indices:
        assert idx < H, "Only non-hardened derivation supported"
        data = pubkey + struct.pack('>I', idx)
        I = hmac.new(chaincode, data, hashlib.sha512).digest()
        IL, IR = I[:32], I[32:]
        # child_pubkey = point(IL) + parent_pubkey
        IL_pub = ec_pubkey(IL)
        pubkey = ec_point_add(IL_pub, pubkey)
        chaincode = IR

    return pubkey


def xpub_fingerprint(xpub_str):
    """Get the master fingerprint from a root xpub."""
    raw = base58.b58decode_check(xpub_str)
    pubkey = raw[45:78]
    return hash160(pubkey)[:4]


# ---------------------------------------------------------------------------
#  Helpers: PSBT parsing (minimal, for verification)
# ---------------------------------------------------------------------------

def read_compact_size(data, offset):
    b = data[offset]
    if b < 0xfd:
        return b, offset + 1
    elif b == 0xfd:
        return struct.unpack_from('<H', data, offset + 1)[0], offset + 3
    elif b == 0xfe:
        return struct.unpack_from('<I', data, offset + 1)[0], offset + 5
    else:
        return struct.unpack_from('<Q', data, offset + 1)[0], offset + 9


def parse_psbt_sections(data):
    """Parse raw PSBT bytes into sections of key-value dicts.
    Returns (globals, [inputs], [outputs]).
    Each section is a list of (key_type, key_data, value) tuples.
    """
    assert data[:5] == b'psbt\xff', "Bad PSBT magic"
    pos = 5

    sections = []
    current = []

    while pos < len(data):
        key_len, pos = read_compact_size(data, pos)
        if key_len == 0:
            sections.append(current)
            current = []
            continue
        key = data[pos:pos + key_len]
        pos += key_len
        val_len, pos = read_compact_size(data, pos)
        val = data[pos:pos + val_len]
        pos += val_len
        current.append((key[0], key[1:], val))

    if current:
        sections.append(current)

    # First section is globals, then inputs, then outputs
    return sections


def find_field(section, key_type):
    """Find first field with given key_type in a section."""
    for kt, kd, v in section:
        if kt == key_type:
            return (kd, v)
    return None


def parse_args():
    parser = argparse.ArgumentParser(description='Run end-to-end PSBT signing tests against a Jade device.')
    parser.add_argument('serialport', nargs='?', default=None,
                        help='Serial device path. Defaults to auto-detect.')
    parser.add_argument('--serial-timeout', dest='serial_timeout', type=float,
                        default=DEFAULT_SERIAL_TIMEOUT,
                        help=f'Per-read serial timeout in seconds (default: {DEFAULT_SERIAL_TIMEOUT:g}).')
    parser.add_argument('--boot-timeout', dest='boot_timeout', type=float,
                        default=DEFAULT_BOOT_TIMEOUT,
                        help=f'Maximum time to wait for Jade to answer after connect (default: {DEFAULT_BOOT_TIMEOUT:g}).')
    parser.add_argument('--poll-interval', dest='poll_interval', type=float,
                        default=DEFAULT_POLL_INTERVAL,
                        help=f'Polling interval while waiting for Jade to boot (default: {DEFAULT_POLL_INTERVAL:g}).')
    return parser.parse_args()


def wait_for_version_info(jade, boot_timeout, poll_interval):
    deadline = time.monotonic() + boot_timeout
    last_error = None
    waiting_message_printed = False

    while time.monotonic() < deadline:
        try:
            return jade.get_version_info(nonblocking=True)
        except (EOFError, JadeError, AssertionError) as exc:
            last_error = exc
            if not waiting_message_printed:
                print("Waiting for Jade to finish booting and answer RPCs...", flush=True)
                waiting_message_printed = True
            time.sleep(poll_interval)

    raise TimeoutError(
        f"Timed out waiting for Jade after {boot_timeout:g}s. "
        f"Last error: {last_error!r}"
    )


def unlock_if_needed(jade, info):
    state = info.get('JADE_STATE', '?')
    print(f"Jade version: {info.get('JADE_VERSION', '?')} (state={state})", flush=True)

    if state == 'READY':
        print("Device is already unlocked.", flush=True)
        return

    if not info.get('JADE_HAS_PIN', False):
        print("Device has no PIN set; continuing without auth.", flush=True)
        return

    print("Requesting unlock on Jade now...", flush=True)
    while True:
        try:
            if jade.auth_user('litecoin', http_request_fn=pinserver_http_request) is True:
                break
            print("Incorrect PIN entered. Try again on the Jade device.", flush=True)
        except JadeError as exc:
            if exc.code == JadeError.USER_CANCELLED:
                raise SystemExit("Unlock cancelled on Jade.")
            print(f"Unlock failed: {exc}", flush=True)
            raise
    print("Unlocked!", flush=True)


def pinserver_http_request(params):
    use_json = params.get('accept') in ('json', 'application/json')
    url = next((candidate for candidate in params['urls'] if not candidate.endswith('.onion')), None)
    if url is None:
        return {'body': None}

    data = None
    headers = {}
    if use_json:
        headers['Accept'] = 'application/json'

    if params['method'] == 'POST':
        payload = params['data']
        if use_json:
            data = json.dumps(payload).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        elif isinstance(payload, str):
            data = payload.encode('utf-8')
        else:
            data = payload
    elif params['method'] != 'GET':
        raise ValueError(f"Unsupported HTTP method: {params['method']}")

    request = urllib.request.Request(url, data=data, headers=headers, method=params['method'])

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
            if use_json:
                return {'body': json.loads(body.decode(response.headers.get_content_charset() or 'utf-8'))}

            content_type = response.headers.get_content_type()
            charset = response.headers.get_content_charset()
            if charset or content_type.startswith('text/'):
                return {'body': body.decode(charset or 'utf-8')}
            return {'body': body}
    except urllib.error.URLError:
        return {'body': None}


def get_mweb_context(jade):
    print("  Exporting scan key... (confirm on device)")
    scan_key = bytes(jade.get_mweb_scan_key('litecoin'))
    scan_pub = ec_pubkey(scan_key)

    root_xpub = jade.get_xpub('litecoin', [])
    fingerprint_bytes = xpub_fingerprint(root_xpub)
    fingerprint = struct.unpack('<I', fingerprint_bytes)[0]

    spend_path = [H | 0, H | 100, H | 1]
    spend_xpub_str = jade.get_xpub('litecoin', spend_path)
    spend_xpub_bytes = base58.b58decode_check(spend_xpub_str)
    spend_pub = spend_xpub_bytes[-33:]

    print(f"  Scan key: {scan_key.hex()}", flush=True)
    print(f"  Scan pubkey: {scan_pub.hex()}", flush=True)
    print(f"  Master fingerprint: {fingerprint:08x}", flush=True)
    print(f"  Spend pubkey: {spend_pub.hex()}", flush=True)

    return {
        'scan_key': scan_key,
        'scan_pub': scan_pub,
        'spend_pub': spend_pub,
        'fingerprint': fingerprint,
        'fingerprint_bytes': fingerprint_bytes,
        'scan_path': [H | 0, H | 100, H | 0],
        'spend_path': spend_path,
    }


# ---------------------------------------------------------------------------
#  Test 1: Standard LTC PSBTv0
# ---------------------------------------------------------------------------

def test_standard_ltc(jade):
    print("\n=== Test 1: Standard LTC PSBTv0 Signing ===\n")

    # 1. Get fingerprint + xpub (minimize Jade calls to avoid timeout)
    root_xpub = jade.get_xpub('litecoin', [])
    fingerprint_bytes = xpub_fingerprint(root_xpub)
    fingerprint = struct.unpack('<I', fingerprint_bytes)[0]
    print(f"  Master fingerprint: {fingerprint:08x}", flush=True)

    account_xpub = jade.get_xpub('litecoin', [H | 84, H | 2, H | 0])
    print(f"  xpub (m/84'/2'/0'): {account_xpub}", flush=True)

    # Derive child pubkey at m/84'/2'/0'/0/0 locally (non-hardened)
    child_pubkey = bip32_derive_child_pubkey(account_xpub, 0, 0)
    print(f"  Child pubkey (m/84'/2'/0'/0/0): {child_pubkey.hex()}", flush=True)

    # 2. Build P2WPKH scriptPubKey
    pkh = hash160(child_pubkey)
    spk = p2wpkh_script(pkh)
    print(f"  P2WPKH scriptPubKey: {spk.hex()}", flush=True)

    # 3. Create a fake previous transaction paying to our address
    input_amount = 100000  # 0.001 LTC
    fake_prev_tx = serialize_tx(
        version=2,
        inputs=[(b'\x00' * 32, 0xffffffff, b'\x01\x00', 0xffffffff)],  # coinbase-like
        outputs=[(input_amount, spk)],
        locktime=0,
    )
    prev_txid = txid_of(fake_prev_tx)
    print(f"  Fake prev txid: {prev_txid[::-1].hex()}", flush=True)

    # 4. Build the unsigned spending transaction
    output_amount = 90000  # fee = 10000
    # Dummy destination: OP_RETURN
    dest_script = b'\x6a\x04test'  # OP_RETURN "test"

    unsigned_tx = serialize_tx(
        version=2,
        inputs=[(prev_txid, 0, b'', 0xfffffffd)],
        outputs=[(output_amount, dest_script)],
        locktime=0,
    )

    # 5. Build PSBTv0
    psbt = b'psbt\xff'

    # Global: unsigned tx (type 0x00)
    psbt += kv(0x00, b'', unsigned_tx)
    psbt += separator()

    # Input 0: witness_utxo (type 0x01) + BIP32 derivation (type 0x06)
    wutxo = witness_utxo(input_amount, spk)
    path = [H | 84, H | 2, H | 0, 0, 0]
    psbt += kv(0x01, b'', wutxo)
    psbt += bip32_derivation_kv(child_pubkey, fingerprint, path)
    psbt += separator()

    # Output 0: empty (no metadata needed for OP_RETURN)
    psbt += separator()

    print(f"  PSBT size: {len(psbt)} bytes", flush=True)
    print(f"  Sending to Jade for signing... (confirm on device)", flush=True)

    # 6. Sign
    signed_psbt = jade.sign_psbt('litecoin', psbt)
    print(f"  Signed PSBT size: {len(signed_psbt)} bytes", flush=True)

    # 7. Parse and verify signature
    sections = parse_psbt_sections(bytes(signed_psbt))
    assert len(sections) >= 2, "Expected at least global + 1 input section"

    input_section = sections[1]
    sig_field = find_field(input_section, 0x02)  # PARTIAL_SIG
    if sig_field:
        sig_pubkey, sig_value = sig_field
        print(f"  Signature found!", flush=True)
        print(f"    Pubkey: {sig_pubkey.hex()}", flush=True)
        print(f"    Sig ({len(sig_value)} bytes): {sig_value.hex()}", flush=True)
        print("\n  *** Test 1 PASSED ***")
        return True
    else:
        print("  ERROR: No partial signature found in signed PSBT!")
        print("  Fields in input section:")
        for kt, kd, v in input_section:
            print(f"    type=0x{kt:02x} key_data={kd.hex()} value_len={len(v)}", flush=True)
        print("\n  *** Test 1 FAILED ***")
        return False


# ---------------------------------------------------------------------------
#  Test 2: MWEB Input Signing
# ---------------------------------------------------------------------------

def test_mweb(jade, mweb_ctx):
    print("\n=== Test 2: MWEB Input Signing (standalone RPC) ===\n")

    scan_key = mweb_ctx['scan_key']
    scan_pub = mweb_ctx['scan_pub']
    spend_pub = mweb_ctx['spend_pub']

    print(f"  Scan key: {scan_key.hex()}", flush=True)
    print(f"  Scan pubkey: {scan_pub.hex()}", flush=True)
    print(f"  Master fingerprint: {mweb_ctx['fingerprint']:08x}", flush=True)
    print(f"  Spend pubkey: {spend_pub.hex()}", flush=True)

    # 2. Generate random key exchange keypair
    kex_secret = random_valid_secret()
    kex_pk = ec_pubkey(kex_secret)
    print(f"  Key exchange pubkey: {kex_pk.hex()}", flush=True)

    # 3. Derive MWEB output key for address_index=0
    address_index = 0
    shared_secret, Ko = derive_mweb_spent_output_pubkey(
        scan_key, spend_pub, address_index, kex_pk)
    print(f"  Shared secret: {shared_secret.hex()}", flush=True)
    print(f"  Expected output key (Ko): {Ko.hex()}", flush=True)

    # 4. Sign the MWEB input directly.
    # Current firmware support for pure-MWEB PSBT signing is still tripping the
    # standard UTXO validation path; use the dedicated RPC for stable coverage.
    spent_output_id = os.urandom(32)
    input_amount = 100000  # 0.001 LTC
    features = 0x01  # STEALTH_KEY_BIT

    print("  Sending MWEB input to Jade for signing... (confirm on device)", flush=True)
    result = jade.sign_mweb_input(
        'litecoin',
        features,
        spent_output_id,
        Ko,
        input_amount,
        kex_pk,
        address_index,
    )

    signature = bytes(result['signature'])
    input_blind = bytes(result['input_blind'])
    stealth_tweak = bytes(result['stealth_tweak'])
    input_pubkey = bytes(result['input_pubkey'])
    output_commit = bytes(result['output_commit'])

    print(f"  Signature ({len(signature)} bytes): {signature.hex()}", flush=True)
    print(f"  Input blind: {input_blind.hex()}", flush=True)
    print(f"  Stealth tweak: {stealth_tweak.hex()}", flush=True)
    print(f"  Input pubkey: {input_pubkey.hex()}", flush=True)
    print(f"  Output commit: {output_commit.hex()}", flush=True)

    assert len(signature) == 64, f"Expected 64-byte MWEB signature, got {len(signature)}"
    assert len(input_blind) == 32, f"Expected 32-byte input blind, got {len(input_blind)}"
    assert len(stealth_tweak) == 32, f"Expected 32-byte stealth tweak, got {len(stealth_tweak)}"
    assert len(input_pubkey) == 33, f"Expected 33-byte input pubkey, got {len(input_pubkey)}"
    assert len(output_commit) == 33, f"Expected 33-byte output commit, got {len(output_commit)}"
    assert any(signature), "MWEB signature is all zeroes"
    assert any(input_blind), "MWEB input blind is all zeroes"
    assert any(stealth_tweak), "MWEB stealth tweak is all zeroes"
    assert output_commit[0] in (0x08, 0x09), f"Bad commit prefix: 0x{output_commit[0]:02x}"

    print("\n  *** Test 2 PASSED ***")
    return True


def test_mweb_psbt(jade, mweb_ctx):
    print("\n=== Test 3: MWEB PSBTv2 Signing (sign_psbt) ===\n")

    scan_key = mweb_ctx['scan_key']
    spend_pub = mweb_ctx['spend_pub']
    fingerprint_bytes = mweb_ctx['fingerprint_bytes']

    input_address_index = 0
    output_address_index = 1
    input_amount = 100000
    output_amount = 90000
    kernel_fee = input_amount - output_amount
    input_features = 0x01  # STEALTH_KEY_BIT
    output_features = 0x01  # STANDARD_FIELDS_BIT

    kex_secret = random_valid_secret()
    kex_pk = ec_pubkey(kex_secret)
    shared_secret, spent_output_pubkey = derive_mweb_spent_output_pubkey(
        scan_key, spend_pub, input_address_index, kex_pk)
    spent_output_id = os.urandom(32)
    spent_output_commit = b'\x08' + os.urandom(32)

    dest_Ai, dest_Bi = derive_mweb_stealth_components(
        scan_key, spend_pub, output_address_index)
    stealth_address = dest_Ai + dest_Bi

    print(f"  Shared secret: {shared_secret.hex()}", flush=True)
    print(f"  Key exchange pubkey: {kex_pk.hex()}", flush=True)
    print(f"  Spent output id: {spent_output_id.hex()}", flush=True)
    print(f"  Spent output pubkey: {spent_output_pubkey.hex()}", flush=True)
    print(f"  Destination stealth payload: {stealth_address.hex()}", flush=True)
    print(f"  Input amount: {input_amount}", flush=True)
    print(f"  Output amount: {output_amount}", flush=True)
    print(f"  Kernel fee: {kernel_fee}", flush=True)

    # Build a canonical pure-MWEB PSBTv2 matching ltcsuite/python-psbt:
    # - no PREVOUT_HASH / PREVOUT_INDEX for the MWEB input
    # - one MWEB output (amount + stealth address)
    # - one kernel carrying the fee
    psbt = b'psbt\xff'
    psbt += kv(0xfb, b'', struct.pack('<I', 2))  # PSBT version
    psbt += kv(0x02, b'', struct.pack('<I', 2))  # tx version
    psbt += kv(0x04, b'', compact_size(1))       # input count
    psbt += kv(0x05, b'', compact_size(1))       # output count
    psbt += kv(0x92, b'', compact_size(1))       # kernel count
    psbt += separator()

    psbt += kv(0x90, b'', spent_output_id)
    psbt += kv(0x91, b'', spent_output_commit)
    psbt += kv(0x92, b'', spent_output_pubkey)
    psbt += kv(0x94, b'', bytes([input_features]))
    psbt += kv(0x96, b'', struct.pack('<I', input_address_index))
    psbt += kv(0x97, b'', struct.pack('<Q', input_amount))
    psbt += kv(0x99, b'', kex_pk)
    psbt += key_origin_kv(0x9A, mweb_ctx['scan_pub'], fingerprint_bytes, mweb_ctx['scan_path'])
    psbt += key_origin_kv(0x9B, spend_pub, fingerprint_bytes, mweb_ctx['spend_path'])
    psbt += separator()

    psbt += kv(0x03, b'', struct.pack('<Q', output_amount))
    psbt += kv(0x90, b'', stealth_address)
    psbt += kv(0x92, b'', bytes([output_features]))
    psbt += separator()

    psbt += kv(0x02, b'', struct.pack('<Q', kernel_fee))
    psbt += separator()

    print(f"  PSBT size: {len(psbt)} bytes", flush=True)
    print(f"  PSBT hex: {psbt.hex()}", flush=True)

    # Self-check: verify structure with our simple parser
    sections = parse_psbt_sections(psbt)
    print(f"  Self-check: {len(sections)} sections parsed", flush=True)
    for si, sec in enumerate(sections):
        types = [f"0x{kt:02x}" for kt, _, _ in sec]
        print(f"    section {si}: {types}", flush=True)

    print("  Sending to Jade for signing... (confirm MWEB output and fee on device)", flush=True)

    signed_psbt = jade.sign_psbt('litecoin', psbt)
    print(f"  Signed PSBT size: {len(signed_psbt)} bytes", flush=True)
    print(f"  Signed PSBT hex: {bytes(signed_psbt).hex()}", flush=True)

    sections = parse_psbt_sections(bytes(signed_psbt))
    assert len(sections) >= 4, "Expected global, input, output, and kernel sections"

    global_section = sections[0]
    input_section = sections[1]
    output_section = sections[2]
    kernel_section = sections[3]

    tx_offset_field = find_field(global_section, 0x90)
    stealth_offset_field = find_field(global_section, 0x91)
    input_sig_field = find_field(input_section, 0x95)
    input_pubkey_field = find_field(input_section, 0x93)
    commit_field = find_field(input_section, 0x91)

    assert tx_offset_field is not None, "Missing MWEB tx offset in globals"
    assert stealth_offset_field is not None, "Missing MWEB stealth offset in globals"
    assert input_sig_field is not None, "Missing MWEB input signature"
    assert input_pubkey_field is not None, "Missing MWEB input pubkey"
    assert commit_field is not None, "Missing MWEB spent output commit"
    assert find_field(output_section, 0x90) is not None, "Missing MWEB stealth address output"
    assert find_field(kernel_section, 0x02) is not None, "Missing MWEB kernel fee"

    tx_offset = tx_offset_field[1]
    stealth_offset = stealth_offset_field[1]
    input_sig = input_sig_field[1]
    input_pubkey = input_pubkey_field[1]
    output_commit = commit_field[1]

    print(f"  MWEB tx offset: {tx_offset.hex()}", flush=True)
    print(f"  MWEB stealth offset: {stealth_offset.hex()}", flush=True)
    print(f"  MWEB input signature ({len(input_sig)} bytes): {input_sig.hex()}", flush=True)
    print(f"  MWEB input pubkey: {input_pubkey.hex()}", flush=True)
    print(f"  MWEB output commit: {output_commit.hex()}", flush=True)

    assert len(tx_offset) == 32, f"Expected 32-byte tx offset, got {len(tx_offset)}"
    assert len(stealth_offset) == 32, f"Expected 32-byte stealth offset, got {len(stealth_offset)}"
    assert len(input_sig) == 64, f"Expected 64-byte MWEB signature, got {len(input_sig)}"
    assert len(input_pubkey) == 33, f"Expected 33-byte MWEB input pubkey, got {len(input_pubkey)}"
    assert len(output_commit) == 33, f"Expected 33-byte MWEB output commit, got {len(output_commit)}"
    assert any(tx_offset), "MWEB tx offset is all zeroes"
    assert any(stealth_offset), "MWEB stealth offset is all zeroes"
    assert any(input_sig), "MWEB input signature is all zeroes"
    assert output_commit[0] in (0x08, 0x09), f"Bad commit prefix: 0x{output_commit[0]:02x}"

    print("\n  *** Test 3 PASSED ***")
    return True


# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    passed = 0
    failed = 0

    jade = JadeAPI.create_serial(device=args.serialport, timeout=args.serial_timeout)
    selected_port = jade.jade.impl.device
    port_label = selected_port or 'auto-detected serial device'

    print(f"Connecting to Jade on {port_label}...", flush=True)
    print(
        f"Using serial timeout {args.serial_timeout:g}s and boot timeout {args.boot_timeout:g}s.",
        flush=True,
    )
    jade.connect()

    try:
        info = wait_for_version_info(jade, args.boot_timeout, args.poll_interval)
        unlock_if_needed(jade, info)

        # Test 1
        try:
            if test_standard_ltc(jade):
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"\n  *** Test 1 ERROR: {e} ***")
            import traceback
            traceback.print_exc()
            failed += 1

        mweb_ctx = None

        # Test 2
        try:
            mweb_ctx = get_mweb_context(jade)
            if test_mweb(jade, mweb_ctx):
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"\n  *** Test 2 ERROR: {e} ***")
            import traceback
            traceback.print_exc()
            failed += 1

        # Test 3
        try:
            if mweb_ctx is None:
                mweb_ctx = get_mweb_context(jade)
            if test_mweb_psbt(jade, mweb_ctx):
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"\n  *** Test 3 ERROR: {e} ***")
            import traceback
            traceback.print_exc()
            failed += 1
    finally:
        jade.disconnect()

    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
