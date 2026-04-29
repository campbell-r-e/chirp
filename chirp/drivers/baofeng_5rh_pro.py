# Copyright 2024:
# * Campbell Reed
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Driver for Baofeng UV-5RM Plus (GPS) / 5RH PRO family.

Protocol: 6-step random-seed XOR handshake, 4096-byte blocks, 49152 bytes
total memory.  All wire bytes are XOR'd with a per-session random seed (1-254).
Memory is XOR-decrypted in bulk after a full download.

Boot screen: separate pre-session using "Picture\\xFF" magic (no XOR).
Image is 160x128 RGB565 BE = 40960 bytes (10 x 4096-byte raw blocks).
"""

import logging
import os
import random
import struct
import time

from chirp import chirp_common, directory, errors, memmap
from chirp.settings import (RadioSetting, RadioSettingGroup, RadioSettings,
                            RadioSettingValueBoolean, RadioSettingValueFile,
                            RadioSettingValueInteger, RadioSettingValueList,
                            RadioSettingValueString)

try:
    from PIL import Image as _PILImage
    _PIL_AVAILABLE = True
except ImportError:
    _PILImage = None
    _PIL_AVAILABLE = False

LOG = logging.getLogger(__name__)

# ── Protocol constants ──────────────────────────────────────────────────

BAUD_PRIMARY = 19200
BAUD_FALLBACK = 115200

# Wake pulse: 12 null bytes flush any pending serial state; the trailing
# four 0xFF bytes are the "start of session" sentinel the radio expects.
# The radio always replies to this with a raw (non-XOR'd) 0x41 ACK byte.
_T_INFO = b'\x00' * 12 + b'\xFF' * 4
_MAGIC_PROGRAM = b'PROGRAM'
_MAGIC_INFO = b'INFORMATION'
_MAGIC_END = b'END\x00'
_MAGIC_PICTURE = b'Picture\xFF'               # boot screen magic (no XOR)
_ACK = 0x41

_BLOCK_SIZE = 4096
_MEM_SIZE = 49152    # 0xC000 = 12 × 4096

# ── Memory map offsets (confirmed from DataProtocol.cs) ─────────────────

ADDR_DEVICE = 0x0000   # 128 bytes
ADDR_CHANNELS = 0x0080   # 640 × 48 = 30720 bytes
ADDR_VFO = 0x7900   # 2 × 48 = 96 bytes
ADDR_SETTINGS = 0x7980   # 128 bytes
ADDR_CHN_FLAGS = 0x7A20   # 80 bytes  (640 / 8)
ADDR_ZONE_CNT = 0x7A80   # 1 byte    (zone count)
ADDR_ZONES = 0x7A90   # 10 × 152 = 1520 bytes
ADDR_SCAN_FREQ = 0x8100   # 10 × 8  = 80 bytes
ADDR_SCAN_PARA = 0x8180   # 32 bytes
ADDR_SCAN_FLAGS = 0x81A0   # 80 bytes  (640 / 8)
ADDR_DTMF = 0x8200   # 88 bytes system params
ADDR_DTMF_FLAGS = 0x8258   # 8 bytes   (16 enable flags as u16 LE + padding)
ADDR_DTMF_ENC = 0x8260   # 16 × 16 = 256 bytes encode IDs
ADDR_2TONE = 0x8400   # 8 bytes   system params
ADDR_2TONE_ENC = 0x8410   # 16 × 16 = 256 bytes encode list
ADDR_2TONE_DEC = 0x8510   # 16 bytes  decode params
ADDR_5TONE_ENC = 0x8680   # 100 × 32 = 3200 bytes encode list
ADDR_5TONE_TBL = 0x9380   # 13 bytes  enable bitmap
ADDR_5TONE_PTTID = 0x9400  # 32 bytes  PTT ID frames
ADDR_5TONE_DEC = 0x9440   # 24 bytes  decode params
ADDR_5TONE_INFO = 0x9480   # 8 × 16 = 128 bytes info codes
ADDR_MDC_SYS = 0x9580   # 8 bytes   sys list
ADDR_MDC_PARA = 0x9588   # 5 × 8  = 40 bytes
ADDR_MDC_PTTID = 0x95B0   # 5 × 8  = 40 bytes
ADDR_MDC_TBL = 0x95D8   # 16 bytes  enable bitmap
ADDR_MDC_DEC = 0x95E8   # 100 × 16 = 1600 bytes decode list
ADDR_MDC_BIIS = 0x9C80   # BIIS params
ADDR_EMERG_HDR = 0x9D00   # 8 bytes   header
ADDR_EMERG = 0x9D08   # 10 × 16 = 160 bytes systems
ADDR_APRS = 0x9E00   # 456 bytes
ADDR_GPS_FLAGS = 0xA000   # 10 bytes  (80 / 8)
ADDR_GPS_BOOK = 0xA010   # 80 × 16 = 1280 bytes

_CHN_SIZE = 48
_MAX_CHN = 640

# ── Boot screen dimensions ──────────────────────────────────────────────

_BS_WIDTH = 160
_BS_HEIGHT = 128
_BS_CHUNK = 4096   # raw block size for boot screen upload

# ── Setting value lists ─────────────────────────────────────────────────

LIST_WORKMODE = ['Frequency', 'Channel']
LIST_BANDWIDTH = ['Wide', 'Narrow']
LIST_POWER = ['High', 'Mid', 'Low']
LIST_VOICE = ['Off', 'Chinese', 'English']
LIST_SQUELCH = [str(x) for x in range(0, 10)]
LIST_APO = ['Off', '30 min', '60 min', '120 min', '240 min', '480 min']
LIST_TOT = ['Off'] + ['%d s' % x for x in range(15, 225, 15)]
LIST_BACKLIGHT = ['Always On'] + ['%d s' % x for x in range(5, 31)]
LIST_BLIGHT_LV = [str(x) for x in range(1, 6)]
LIST_GPS_MODE = ['GPS', 'Beidou', 'GPS+Beidou']
LIST_DISP_MODE = ['Frequency', 'Name', 'Channel Number', 'Freq+Name']
LIST_SCAN_MODE = ['Time', 'Carrier', 'Search']
LIST_PTTID = ['Off', 'BOT', 'EOT', 'Both']
LIST_DUPLEX = ['Off', '+', '-']
LIST_OFFSETDIR = ['Off', '+', '-', 'Split']
LIST_SQTYPE = ['Off', 'CTCSS', 'DCS', 'CTCSS/DCS']
LIST_SIGNAL = ['Off', 'DTMF', '2-Tone', '5-Tone', 'MDC-1200']
LIST_BCL = ['Off', 'Carrier', 'Tone']
LIST_END_TONE = ['Off', 'Mode 1', 'Mode 2', 'Mode 3']
LIST_TAIL_FREQ = ['Off', '55 Hz', '120°', '180°', '240°']
LIST_MAIN_BAND = ['A', 'B']
LIST_POWON_FACE = ['Picture', 'Name', 'Battery']
LIST_RTNCH = ['Last', 'Priority', 'Original']
# Byte values must match ProKeyEnum exactly (0-16)
LIST_KEY_FUNC = [
    'None',             # 0
    'Scan On/Off',      # 1
    'Monitor',          # 2
    'Flashlight',       # 3
    'FM Radio',         # 4
    'Emergency',        # 5
    'GPS',              # 6
    'Freq. Measuring',  # 7
    'Bluetooth',        # 8
    '1750 Hz',          # 9
    'Freq. Inversion',  # 10
    'Lone Worker',      # 11
    'Fallen Alarm',     # 12
    'One Touch Call',   # 13
]
LIST_LONEWORK_RSP = ['None', 'Alarm', 'TX Alarm', 'Message']
LIST_POSAVE = ['Off', '1:1', '1:2', '1:4']
LIST_POSAVE_DLY = ['5 s', '10 s', '15 s', '20 s', '25 s']
LIST_VOX_DLY = ['%.1f s' % (1.0 + i * 0.5) for i in range(19)]
LIST_HZ1750 = ['1000 Hz', '1450 Hz', '1750 Hz', '2100 Hz']
LIST_NOAA_CH = ['WX%d' % i for i in range(1, 11)]
LIST_RECORD_MODE = ['RX', 'TX', 'All']
LIST_EMERG_MODE = ['Off', 'TX Alarm', 'TX Code', 'Call & Alarm']
LIST_EMERG_TYPE = ['Continuous', 'Time', 'Alarm Only']
LIST_APRS_POWER = ['Low', 'Mid', 'High']
LIST_MICETYPE = ['Off', 'Type 1', 'Type 2', 'Type 3', 'Type 4',
                 'Type 5', 'Type 6', 'Type 7']
LIST_5TONE_STAND = [
    'ZVEI1', 'ZVEI2', 'ZVEI3', 'PZVEI', 'DZVEI', 'PDZVEI',
    'CCIR1', 'CCIR2', 'PCCIR', 'EEA', 'EIA', 'EURO',
    'NATEL', 'MODAT',
]
LIST_5TONE_CODETIME = ['70 ms', '80 ms', '90 ms', '100 ms', '110 ms', '120 ms']
LIST_5TONE_SCALL = ['Normal', 'Group', 'ANI', 'PTT ID']
LIST_MDC_SYNC = ['Continuous', '40 ms', '80 ms', '120 ms']
LIST_2TONE_DEC_RSP = ['None', 'Alarm', 'TX Alarm']

_CHARSET = chirp_common.CHARSET_ASCII
for _x in range(0xB0, 0xD7):
    for _y in range(0xA1, 0xFF):
        try:
            _CHARSET += bytes([_x, _y]).decode('gb2312')
        except Exception:
            pass

DTMF_CHARS = '0123456789ABCD*#'

# ── Tone helpers ────────────────────────────────────────────────────────


def _decode_tone(datH, datL):
    # Wire format: datH bit7 set → DCS (bit6 set = inverted polarity,
    # bits[10:8] in datH bits[2:0], code digits in datL).
    # datH bit7 clear → CTCSS stored as BCD-over-hex: 0x0885 = 88.5 Hz.
    if datH == 0x00 or datH == 0xFF:
        return '', 0, 'N'
    if datH & 0x80:
        pol = 'R' if (datH & 0xC0) == 0xC0 else 'N'
        code_val = ((datH & 0x07) << 8) | datL
        code = int('%x' % code_val)
        return 'DTCS', code, pol
    else:
        raw = (datH << 8) | datL
        bcd_decimal = int('%x' % raw)   # treat hex digits as decimal
        tone_hz = bcd_decimal / 10.0
        return 'Tone', tone_hz, 'N'


def _encode_tone(mode, tone, pol):
    # Inverse of _decode_tone — CTCSS as BCD-over-hex, DCS with bit flags.
    if mode == '' or mode is None:
        return 0x00, 0x00
    if mode == 'Tone':
        bcd_decimal = int(round(tone * 10))
        raw = int('%d' % bcd_decimal, 16)
        return (raw >> 8) & 0x7F, raw & 0xFF
    if mode == 'TSQL':
        bcd_decimal = int(round(tone * 10))
        raw = int('%d' % bcd_decimal, 16)
        return (raw >> 8) & 0x7F, raw & 0xFF
    if mode == 'DTCS':
        code_val = int('%d' % int(tone), 16)
        h = 0x80 | ((code_val >> 8) & 0x07)
        if pol == 'R':
            h |= 0x40
        return h, code_val & 0xFF
    return 0x00, 0x00


# ── Frequency helpers ───────────────────────────────────────────────────

def _decode_freq(data4):
    le_int = struct.unpack_from('<I', bytes(data4))[0]
    bcd_str = '%08X' % le_int
    bcd_dec = int(bcd_str)
    return bcd_dec * 10


def _encode_freq(hz):
    units = hz // 10
    bcd_str = '%08d' % units
    le_int = int(bcd_str, 16)
    return struct.pack('<I', le_int)


def _decode_freq_le(data4):
    """Decode a plain LE uint32 frequency (units = 10 Hz). Used for VFO,
    scan, and APRS TX frequency fields."""
    return struct.unpack_from('<I', bytes(data4))[0] * 10


def _encode_freq_le(hz):
    """Encode a frequency as plain LE uint32 (units = 10 Hz)."""
    return struct.pack('<I', hz // 10)


# ── 5-Tone packed-nibble helpers ────────────────────────────────────────
# Digits: 0-9 → '0'-'9', 10 → 'A', 11 → 'B', 12 → 'C', 13 → 'D',
#         14 → '*', 15 → '#'
_5TONE_DIGIT = '0123456789ABCD*#'


def _decode_5tone_id(raw_bytes, code_len):
    """Decode packed-nibble 5-tone IDs to string (hi nibble first)."""
    result = ''
    for i in range(min(code_len, len(raw_bytes) * 2)):
        byte_idx = i // 2
        if i % 2 == 0:
            nib = (raw_bytes[byte_idx] >> 4) & 0x0F
        else:
            nib = raw_bytes[byte_idx] & 0x0F
        result += _5TONE_DIGIT[nib]
    return result


def _encode_5tone_id(s, max_bytes=20):
    """Encode a digit string to packed-nibble bytes (hi nibble first)."""
    buf = bytearray(max_bytes)
    for i, ch in enumerate(s[:max_bytes * 2]):
        if ch in _5TONE_DIGIT:
            nib = _5TONE_DIGIT.index(ch)
        else:
            nib = 0
        byte_idx = i // 2
        if i % 2 == 0:
            buf[byte_idx] = (buf[byte_idx] & 0x0F) | (nib << 4)
        else:
            buf[byte_idx] = (buf[byte_idx] & 0xF0) | nib
    return bytes(buf)


# ── GB2312 byte-swapped string helpers ──────────────────────────────────

def _decode_name(raw16):
    result = bytearray()
    for b in raw16:
        if b == 0xFF or b == 0x00:
            break
        result.append(b)
    try:
        return result.decode('gb2312').rstrip()
    except UnicodeDecodeError:
        return result.decode('latin-1', errors='replace').rstrip()


def _encode_name(text, maxbytes=16):
    try:
        encoded = text.encode('gb2312')[:maxbytes]
    except (UnicodeEncodeError, LookupError):
        encoded = text.encode('ascii', errors='replace')[:maxbytes]
    if not encoded:
        return b'\x00' * maxbytes
    return encoded.ljust(maxbytes, b'\xFF')


# ── DTMF character helpers ──────────────────────────────────────────────

def _decode_dtmf_bytes(data, maxlen=16):
    """Decode raw DTMF digit bytes (0-15) to string."""
    result = ''
    for i in range(min(len(data), maxlen)):
        b = data[i]
        if b <= 9:
            result += chr(b + 0x30)
        elif 10 <= b <= 13:
            result += chr(b + 55)
        elif b == 14:
            result += '*'
        elif b == 15:
            result += '#'
        else:
            break
    return result


def _encode_dtmf_bytes(s, fieldlen=16):
    """Encode DTMF string to raw digit bytes, 0xFF-padded."""
    out = bytearray(fieldlen)
    for i in range(fieldlen):
        out[i] = 0xFF
    for i, c in enumerate(s[:fieldlen]):
        if c.isdigit():
            out[i] = int(c)
        elif c.upper() in 'ABCD':
            out[i] = ord(c.upper()) - 55
        elif c == '*':
            out[i] = 14
        elif c == '#':
            out[i] = 15
        else:
            break
    return bytes(out)


# ── Boot screen image helpers ───────────────────────────────────────────

def _bs_read_bmp(path):
    """Read a 24-bit BMP file without Pillow.  Returns (rows, w, h)."""
    with open(path, 'rb') as f:
        data = f.read()
    if data[:2] != b'BM':
        raise errors.RadioError('Not a BMP file: %s' % path)
    pixel_offset = struct.unpack_from('<I', data, 10)[0]
    w = struct.unpack_from('<i', data, 18)[0]
    h = struct.unpack_from('<i', data, 22)[0]
    bpp = struct.unpack_from('<H', data, 28)[0]
    if bpp != 24:
        raise errors.RadioError(
            'Boot screen: unsupported format — BMP must be 24-bit RGB '
            '(got %d-bit). Re-save as a 24-bit BMP.' % bpp)
    flip = h > 0
    h = abs(h)
    row_bytes = (w * 3 + 3) & ~3
    rows = []
    for row in range(h):
        src = row if not flip else (h - 1 - row)
        off = pixel_offset + src * row_bytes
        row_pixels = []
        for col in range(w):
            o = off + col * 3
            b, g, r = data[o], data[o + 1], data[o + 2]
            row_pixels.append((r, g, b))
        rows.append(row_pixels)
    return rows, w, h


def _bs_scale_nn(rows, sw, sh, dw, dh):
    """Nearest-neighbour scale."""
    out = []
    for dy in range(dh):
        sy = int(dy * sh / dh)
        row = []
        for dx in range(dw):
            sx = int(dx * sw / dw)
            row.append(rows[sy][sx])
        out.append(row)
    return out


def _bs_rows_to_rgb565(rows):
    buf = bytearray()
    for row in rows:
        for r, g, b in row:
            # Pack as RGB565 BE: bits 15-11=R(5), 10-5=G(6), 4-0=B(5)
            # High byte first (matches CPS ReversalHighLowByte + LE store)
            px = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
            buf.append((px >> 8) & 0xFF)  # high byte first (big-endian)
            buf.append(px & 0xFF)
    return bytes(buf)


def _bs_image_to_rgb565(img_path):
    """Convert any image file to RGB565 BE bytes for 160x128 boot screen."""
    ext = os.path.splitext(img_path)[1].lower()
    if ext == '.bmp':
        rows, w, h = _bs_read_bmp(img_path)
        if w != _BS_WIDTH or h != _BS_HEIGHT:
            rows = _bs_scale_nn(rows, w, h, _BS_WIDTH, _BS_HEIGHT)
        data = _bs_rows_to_rgb565(rows)
    else:
        if not _PIL_AVAILABLE:
            raise errors.RadioError(
                'Boot screen: unsupported format — only .bmp files '
                'are supported.')
        img = _PILImage.open(img_path).convert('RGB')
        if img.width != _BS_WIDTH or img.height != _BS_HEIGHT:
            img = img.resize((_BS_WIDTH, _BS_HEIGHT), _PILImage.LANCZOS)
        # Pack each pixel as RGB565 BE: bits 15-11=R(5), 10-5=G(6), 4-0=B(5)
        # High byte first (matches CPS ReversalHighLowByte + LE store)
        buf = bytearray(_BS_WIDTH * _BS_HEIGHT * 2)
        pixels = img.load()
        for y in range(_BS_HEIGHT):
            for x in range(_BS_WIDTH):
                r, g, b = pixels[x, y]
                px = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
                i = (y * _BS_WIDTH + x) * 2
                buf[i] = (px >> 8) & 0xFF      # high byte first (big-endian)
                buf[i + 1] = px & 0xFF
        data = bytes(buf)
    rem = len(data) % _BS_CHUNK
    if rem:
        data += b'\xFF' * (_BS_CHUNK - rem)
    return data


# ── Boot screen upload (5RH PRO protocol, no XOR) ───────────────────────

def _upload_boot_screen_5rh(radio, img_data):
    """Upload RGB565 image to 5RH PRO boot screen.

    Protocol: T_INFO wake → raw 0x41 → "Picture\\xFF" → raw 0x41 →
    4096-byte raw blocks each followed by raw 0x41 → "END\\x00" → raw 0x41.
    No XOR encryption.
    """
    pipe = radio.pipe

    status = chirp_common.Status()
    status.max = len(img_data) // _BS_CHUNK + 2
    status.cur = 0
    status.msg = 'Boot screen: connecting...'
    radio.status_fn(status)

    # Step 1: wake pulse — Picture mode ACKs with 0xE0 (normal mode uses 0x41)
    _BS_WAKE_ACKS = (0x41, 0xE0)
    pipe.write(_T_INFO)
    pipe.timeout = 1.0
    b = pipe.read(1)
    if not b or b[0] not in _BS_WAKE_ACKS:
        # Try 115200
        pipe.baudrate = BAUD_FALLBACK
        pipe.write(_T_INFO)
        pipe.timeout = 1.0
        b = pipe.read(1)
        if not b or b[0] not in _BS_WAKE_ACKS:
            raise errors.RadioError('Boot screen: no ACK after wake pulse')
    # Drain any trailing bytes after the wake ACK (same firmware quirk as main clone)
    pipe.timeout = 0.05
    pipe.read(16)

    # Step 2: send "Picture\xFF" magic
    pipe.write(_MAGIC_PICTURE)
    pipe.timeout = 2.0
    b = pipe.read(1)
    if not b or b[0] != 0x41:
        raise errors.RadioError('Boot screen: no ACK after Picture magic')

    status.cur = 1
    status.msg = 'Boot screen: sending image...'
    radio.status_fn(status)

    # Step 3: send raw 4096-byte blocks
    sent = 0
    total = len(img_data)
    while sent < total:
        chunk = img_data[sent:sent + _BS_CHUNK]
        pipe.write(chunk)
        pipe.timeout = 5.0
        b = pipe.read(1)
        if not b or b[0] != 0x41:
            raise errors.RadioError(
                'Boot screen: no ACK after block at offset %d' % sent)
        sent += _BS_CHUNK
        status.cur += 1
        radio.status_fn(status)

    # Step 4: send END
    pipe.write(_MAGIC_END)
    pipe.timeout = 3.0
    b = pipe.read(1)
    if not b or b[0] != 0x41:
        raise errors.RadioError('Boot screen: no ACK after END')

    status.msg = 'Boot screen: done'
    radio.status_fn(status)


# ── Serial I/O helpers ──────────────────────────────────────────────────
# After the wake pulse, every byte on the wire is XOR'd with a per-session
# seed (1-254).  _xwrite applies the XOR before sending.  _xread returns
# the raw (still-XOR'd) bytes; callers XOR them individually, or the full
# image is bulk-XOR'd after download (see _download_5rh).

def _xwrite(pipe, data, seed):
    pipe.write(bytes(b ^ seed for b in data))


def _xread(pipe, n, timeout=2.0):
    buf = b''
    deadline = time.time() + timeout
    while len(buf) < n and time.time() < deadline:
        chunk = pipe.read(n - len(buf))
        if chunk:
            buf += chunk
    if len(buf) < n:
        raise errors.RadioError(
            'Timeout: got %d of %d bytes' % (len(buf), n))
    return buf


def _wait_ack(pipe, seed, label, timeout=2.0):
    b = _xread(pipe, 1, timeout)
    decoded = b[0] ^ seed   # 0x41 ('A') when XOR'd back is a valid ACK
    if decoded != _ACK:
        LOG.debug('%s: raw=0x%02x seed=0x%02x decoded=0x%02x (expected 0x%02x^seed=0x%02x)',
                  label, b[0], seed, decoded, _ACK, _ACK ^ seed)
        raise errors.RadioError(
            '%s: expected ACK 0x41, got 0x%02x (raw 0x%02x)' %
            (label, decoded, b[0]))


# ── Handshake ───────────────────────────────────────────────────────────
# Six-step handshake (all bytes after the wake pulse are XOR'd with seed):
#   1. T_INFO wake pulse  → raw 0x41
#   2. PROGRAM header (7 XOR'd bytes + plaintext seed at byte 7)  → ACK
#   3. 8-byte password placeholder (0xFF × 8 XOR'd)  → ACK
#   4. INFORMATION magic  → 16-byte XOR'd model string
#   5. Direction byte ('R' or 'W' XOR'd)  → ACK

def _do_handshake(pipe, seed, direction='R'):
    # Step 1: wake pulse — ACK here is always raw 0x41 (seed not yet in use)
    pipe.write(_T_INFO)
    pipe.timeout = 0.3
    ack = pipe.read(1)
    if not ack or ack[0] != 0x41:
        LOG.debug('5RH: no ACK at 19200, trying 115200')
        pipe.baudrate = BAUD_FALLBACK
        pipe.write(_T_INFO)
        pipe.timeout = 0.5
        ack = pipe.read(1)
        if not ack or ack[0] != 0x41:
            raise errors.RadioNoResponse()
    # Some firmware versions send extra bytes after the 0x41 wake ACK
    # (e.g. a status or version byte).  Drain them so they don't pollute
    # the PROGRAM ACK read below.
    pipe.timeout = 0.05
    pipe.read(16)
    pipe.timeout = 2.0

    # Step 2: PROGRAM header — "PROGRAM" XOR'd, then seed byte at index 7
    # (plaintext) so the radio learns the session key for all subsequent I/O.
    hdr = bytearray(8)
    for i, c in enumerate(_MAGIC_PROGRAM):
        hdr[i] = seed ^ c
    hdr[7] = seed   # session key embedded here; radio uses it from now on
    pipe.write(bytes(hdr))
    _wait_ack(pipe, seed, 'PROGRAM ACK')

    # Step 3: password placeholder — radio ignores content; 0xFF × 8 is fine
    _xwrite(pipe, b'\xFF' * 8, seed)
    _wait_ack(pipe, seed, 'Password ACK')

    # Step 4: request model ID — radio replies with 16 XOR'd bytes
    _xwrite(pipe, _MAGIC_INFO, seed)
    raw16 = _xread(pipe, 16)
    model_bytes = bytes(b ^ seed for b in raw16)
    model_str = model_bytes.split(b'\x00')[0].split(b'\xff')[0].decode(
        'ascii', errors='replace')
    LOG.info('5RH PRO model: %r', model_str)

    # Step 5: tell radio read or write; handshake complete after its ACK
    pipe.write(bytes([seed ^ ord(direction)]))
    _wait_ack(pipe, seed, 'Direction ACK')
    return model_bytes


# ── Download / Upload ───────────────────────────────────────────────────

def _download_5rh(radio):
    pipe = radio.pipe
    pipe.baudrate = BAUD_PRIMARY
    pipe.timeout = 2.0
    seed = random.randint(1, 254)
    LOG.debug('5RH download seed: 0x%02x', seed)
    _do_handshake(pipe, seed, 'R')
    # 4096-byte blocks take ~2.14 s at 19200 baud.  Raise pipe.timeout so a
    # single pipe.read() call can collect the full block without splitting.
    pipe.timeout = 3.0

    buf = bytearray(_MEM_SIZE)
    rx_cnt = 0
    status = chirp_common.Status()
    status.max = _MEM_SIZE // _BLOCK_SIZE
    status.msg = 'Cloning from radio...'

    while rx_cnt < _MEM_SIZE:
        # Read request: 0x52 + addr_hi + addr_lo + 0x00, all XOR'd.
        # Radio replies with a 4-byte echo header then 4096 XOR'd data bytes.
        req = bytes([0x52, (rx_cnt >> 8) & 0xFF, rx_cnt & 0xFF, 0x00])
        _xwrite(pipe, req, seed)
        response = _xread(pipe, _BLOCK_SIZE + 4, timeout=8.0)
        buf[rx_cnt:rx_cnt + _BLOCK_SIZE] = response[4:]   # discard header
        rx_cnt += _BLOCK_SIZE
        status.cur = rx_cnt // _BLOCK_SIZE
        radio.status_fn(status)

    _xwrite(pipe, _MAGIC_END, seed)
    _wait_ack(pipe, seed, 'END ACK', timeout=3.0)
    # Data bytes were stored as received (XOR'd); bulk-decode in one pass now.
    for i in range(_MEM_SIZE):
        buf[i] ^= seed
    return bytes(buf)


def _upload_5rh(radio):
    pipe = radio.pipe
    pipe.baudrate = BAUD_PRIMARY
    pipe.timeout = 2.0
    seed = random.randint(1, 254)
    LOG.debug('5RH upload seed: 0x%02x', seed)
    _do_handshake(pipe, seed, 'W')
    # Writing a 4096-byte block takes ~2.14 s at 19200 baud; the radio can't
    # ACK until it has received the entire block.  Raise pipe.timeout so the
    # ACK read doesn't time out during the block transmission window.
    pipe.timeout = 3.0

    data = radio.get_mmap()
    status = chirp_common.Status()
    status.max = _MEM_SIZE // _BLOCK_SIZE
    status.msg = 'Cloning to radio...'

    tx_cnt = 0
    while tx_cnt < _MEM_SIZE:
        # Write packet: 0x57 + addr_hi + addr_lo + 0x00 + 4096 data bytes,
        # entire packet XOR'd with seed in one pass before sending.
        block = bytes(data[tx_cnt:tx_cnt + _BLOCK_SIZE])
        hdr = bytes([0x57, (tx_cnt >> 8) & 0xFF, tx_cnt & 0xFF, 0x00])
        enc = bytes(b ^ seed for b in hdr + block)
        pipe.write(enc)
        _wait_ack(pipe, seed, 'Write 0x%04x' % tx_cnt, timeout=8.0)
        tx_cnt += _BLOCK_SIZE
        status.cur = tx_cnt // _BLOCK_SIZE
        radio.status_fn(status)

    _xwrite(pipe, _MAGIC_END, seed)
    _wait_ack(pipe, seed, 'Upload END ACK', timeout=3.0)


# ── MemoryMap helpers ───────────────────────────────────────────────────

def _mb(mmap, addr):
    return ord(mmap[addr])


def _mwb(mmap, addr, val):
    mmap[addr] = bytes([val & 0xFF])


def _mwrite(mmap, addr, data):
    for i, b in enumerate(data):
        mmap[addr + i] = bytes([b])


def _mread(mmap, addr, n):
    return bytearray(ord(mmap[addr + i]) for i in range(n))


# ── Channel valid-flag bitmap ───────────────────────────────────────────

def _chn_used(mmap, idx):
    byte_val = _mb(mmap, ADDR_CHN_FLAGS + idx // 8)
    return ((byte_val >> (idx % 8)) & 1) == 0


def _set_chn_used(mmap, idx, used):
    addr = ADDR_CHN_FLAGS + idx // 8
    b = _mb(mmap, addr)
    if used:
        b &= ~(1 << (idx % 8))
    else:
        b |= (1 << (idx % 8))
    _mwb(mmap, addr, b)


def _read_chn_raw(mmap, idx):
    off = ADDR_CHANNELS + idx * _CHN_SIZE
    return _mread(mmap, off, _CHN_SIZE)


def _write_chn_raw(mmap, idx, raw48):
    _mwrite(mmap, ADDR_CHANNELS + idx * _CHN_SIZE, raw48)


# ── Radio class ─────────────────────────────────────────────────────────

@directory.register
class BaofengUV5RMPlusGPS(chirp_common.CloneModeRadio):
    """Baofeng UV-5RM Plus (GPS) — 5RH PRO protocol."""

    VENDOR = 'Baofeng'
    MODEL = 'UV-5RM Plus (GPS)'
    BAUD_RATE = BAUD_PRIMARY

    CHANNELS = _MAX_CHN
    MEM_SIZE = _MEM_SIZE

    POWER_LEVELS = [
        chirp_common.PowerLevel('High', watts=10),
        chirp_common.PowerLevel('Mid', watts=5),
        chirp_common.PowerLevel('Low', watts=1),
    ]

    MODES = ['FM', 'NFM']

    # TX: 136-174, 220-260, 400-480 MHz
    # RX adds: 108-136 MHz airband AM, 350-390 MHz, and UHF up to 520 MHz
    VALID_BANDS = [
        (108_000_000, 136_000_000),  # Airband AM (RX only)
        (136_000_000, 174_000_000),  # VHF
        (220_000_000, 260_000_000),  # 220 MHz
        (350_000_000, 390_000_000),  # UHF low (RX only)
        (400_000_000, 520_000_000),  # UHF (TX 400-480, RX to 520)
    ]

    DTCS_CODES = sorted(chirp_common.DTCS_CODES)
    STEPS = [2.5, 5.0, 6.25, 10.0, 12.5, 20.0, 25.0, 50.0]
    VALID_CHARS = _CHARSET
    LENGTH_NAME = 8

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._boot_image_path = ''
        self._boot_image_data = None

    @classmethod
    def get_prompts(cls):
        rp = chirp_common.RadioPrompts()
        rp.pre_download = _(
            'Follow these steps to download:\n'
            '1. Turn off radio\n'
            '2. Connect programming cable\n'
            '3. Turn on radio\n'
            '4. Click OK\n')
        rp.pre_upload = _(
            'Follow these steps to upload:\n'
            '1. Turn off radio\n'
            '2. Connect programming cable\n'
            '3. Turn on radio\n'
            '4. Click OK\n')
        return rp

    def get_features(self):
        rf = chirp_common.RadioFeatures()
        rf.has_settings = True
        rf.has_bank = False
        rf.has_tuning_step = False
        rf.can_odd_split = True
        rf.has_name = True
        rf.has_offset = True
        rf.has_mode = True
        rf.has_dtcs = True
        rf.has_rx_dtcs = True
        rf.has_dtcs_polarity = True
        rf.has_ctone = True
        rf.has_cross = True
        rf.valid_modes = self.MODES
        rf.valid_characters = self.VALID_CHARS
        rf.valid_name_length = self.LENGTH_NAME
        rf.valid_duplexes = ['', '-', '+', 'split', 'off']
        rf.valid_tmodes = ['', 'Tone', 'TSQL', 'DTCS', 'Cross']
        rf.valid_cross_modes = [
            'Tone->Tone', 'DTCS->', '->DTCS',
            'Tone->DTCS', 'DTCS->Tone', '->Tone', 'DTCS->DTCS']
        rf.valid_skips = ['', 'S']
        rf.valid_dtcs_codes = self.DTCS_CODES
        rf.memory_bounds = (1, self.CHANNELS)
        rf.valid_power_levels = self.POWER_LEVELS
        rf.valid_bands = self.VALID_BANDS
        rf.valid_tuning_steps = self.STEPS
        return rf

    # ── Clone I/O ───────────────────────────────────────────────────────────

    def sync_in(self):
        try:
            data = _download_5rh(self)
        except errors.RadioError:
            raise
        except Exception:
            LOG.exception('Unexpected error during download')
            raise errors.RadioError(
                'Unexpected error communicating with radio')
        self._mmap = memmap.MemoryMapBytes(data)

    def sync_out(self):
        if self._boot_image_data:
            try:
                _upload_boot_screen_5rh(self, self._boot_image_data)
                # Radio writes image to flash after END ACK; 5 s gives it
                # enough time to finish before the channel handshake starts.
                time.sleep(5.0)
            except errors.RadioError:
                raise
            except Exception as e:
                raise errors.RadioError('Boot screen upload failed: %s' % e)
            finally:
                try:
                    self.pipe.timeout = 0.1
                    self.pipe.reset_input_buffer()
                except Exception:
                    pass
        try:
            _upload_5rh(self)
        except errors.RadioError:
            raise
        except Exception:
            LOG.exception('Unexpected error during upload')
            raise errors.RadioError(
                'Unexpected error communicating with radio')

    def process_mmap(self):
        pass

    def get_raw_memory(self, number):
        return repr(_read_chn_raw(self._mmap, number - 1))

    # ── Memory access ───────────────────────────────────────────────────────

    def get_memory(self, number):
        mem = chirp_common.Memory()
        mem.number = number
        idx = number - 1

        if not _chn_used(self._mmap, idx):
            mem.empty = True
            return mem

        raw = _read_chn_raw(self._mmap, idx)

        # Frequencies
        mem.freq = _decode_freq(raw[0:4])
        tx_raw = raw[4:8]

        if all(b == 0xFF for b in tx_raw):
            mem.duplex = 'off'
            mem.offset = 0
        else:
            tx_freq = _decode_freq(tx_raw)
            if tx_freq == mem.freq:
                mem.duplex = ''
                mem.offset = 0
            else:
                diff = tx_freq - mem.freq
                if chirp_common.is_split(self.get_features().valid_bands,
                                         mem.freq, tx_freq):
                    mem.duplex = 'split'
                    mem.offset = tx_freq
                elif diff > 0:
                    mem.duplex = '+'
                    mem.offset = diff
                else:
                    mem.duplex = '-'
                    mem.offset = abs(diff)

        # Tones
        tx_mode, tx_val, tx_pol = _decode_tone(raw[10], raw[11])
        rx_mode, rx_val, rx_pol = _decode_tone(raw[8], raw[9])
        chirp_common.split_tone_decode(
            mem, (tx_mode, tx_val, tx_pol), (rx_mode, rx_val, rx_pol))

        # raw[16]: power[7:6], width[5:4], offsetdir[3:2], freqinvert[1],
        # talkaround[0]
        f16 = raw[16]
        power_idx = (f16 >> 6) & 0x03
        mem.power = self.POWER_LEVELS[min(power_idx, 2)]
        is_narrow = bool((f16 >> 4) & 0x03)
        mem.mode = 'NFM' if is_narrow else 'FM'

        # Skip flag
        scan_val = _mb(self._mmap, ADDR_SCAN_FLAGS + idx // 8)
        mem.skip = '' if ((scan_val >> (idx % 8)) & 1) == 0 else 'S'

        # Name — field is 16 bytes to accommodate GB2312 (2 bytes/char), but
        # the radio displays at most LENGTH_NAME (8) characters.  Clamp so
        # any stray non-null bytes beyond the real name stay invisible.
        mem.name = _decode_name(raw[32:48])[:self.LENGTH_NAME]

        # Extra settings
        mem.extra = RadioSettingGroup('Extra', 'extra')
        f17 = raw[17]
        f18 = raw[18]
        f19 = raw[19]
        f20 = raw[20]

        def _exa(name, label, val_obj):
            mem.extra.append(RadioSetting(name, label, val_obj))

        _exa('busylock', 'Busy Channel Lockout',
             RadioSettingValueList(LIST_BCL,
                                   current_index=min((f19 >> 6) & 0x03, 2)))
        _exa('txdis', 'TX Disable',
             RadioSettingValueBoolean(bool((f19 >> 5) & 1)))
        _exa('talkaround', 'Talk Around',
             RadioSettingValueBoolean(bool(f16 & 1)))
        _exa('compand', 'Compander',
             RadioSettingValueBoolean(bool((f20 >> 5) & 1)))
        _exa('scram', 'Scramble',
             RadioSettingValueBoolean(bool((f20 >> 4) & 1)))
        _exa('cepin24bit', 'Freq. Measuring 24-bit',
             RadioSettingValueBoolean(bool((f20 >> 7) & 1)))
        _exa('cepindcs', 'Freq. Measuring DCS',
             RadioSettingValueBoolean(bool((f20 >> 6) & 1)))
        _exa('freqinvert', 'Frequency Inversion',
             RadioSettingValueBoolean(bool((f16 >> 1) & 1)))
        _exa('signaltype', 'Signal Type',
             RadioSettingValueList(LIST_SIGNAL,
                                   current_index=min((f18 >> 5) & 0x07, 4)))
        _exa('sqtype', 'Squelch Type',
             RadioSettingValueList(LIST_SQTYPE,
                                   current_index=min(f17 & 0x0F, 3)))
        _exa('fivetoneptt', '5-Tone PTT ID',
             RadioSettingValueList(LIST_PTTID,
                                   current_index=min((f17 >> 6) & 0x03, 3)))
        _exa('dtmfptt', 'DTMF PTT ID',
             RadioSettingValueList(LIST_PTTID,
                                   current_index=min((f17 >> 4) & 0x03, 3)))
        _exa('jumpfreq', 'Jump Frequency',
             RadioSettingValueInteger(0, 3, f18 & 0x03))
        _exa('freqstep', 'Frequency Step',
             RadioSettingValueInteger(0, 7, raw[24]))
        _exa('dtmfidx', 'DTMF Index',
             RadioSettingValueInteger(0, 15, raw[25]))
        _exa('twotoneidx', '2-Tone Index',
             RadioSettingValueInteger(0, 15, raw[26]))
        _exa('fivetoneidx', '5-Tone Index',
             RadioSettingValueInteger(0, 99, raw[27]))
        _exa('mdcidx', 'MDC Index',
             RadioSettingValueInteger(0, 7, raw[28]))
        _exa('scanlist', 'Scan List',
             RadioSettingValueInteger(0, 9, raw[29]))
        _exa('emerglist', 'Emergency List',
             RadioSettingValueInteger(0, 9, raw[30]))

        return mem

    def set_memory(self, mem):
        idx = mem.number - 1
        mmap = self._mmap

        if mem.empty:
            _write_chn_raw(mmap, idx, bytes(_CHN_SIZE))
            _set_chn_used(mmap, idx, False)
            return

        raw = bytearray(_CHN_SIZE)

        # Frequencies
        raw[0:4] = _encode_freq(mem.freq)
        if mem.duplex == 'off':
            raw[4:8] = b'\xFF\xFF\xFF\xFF'
        elif mem.duplex == 'split':
            raw[4:8] = _encode_freq(mem.offset)
        elif mem.duplex == '+':
            raw[4:8] = _encode_freq(mem.freq + mem.offset)
        elif mem.duplex == '-':
            raw[4:8] = _encode_freq(mem.freq - mem.offset)
        else:
            raw[4:8] = _encode_freq(mem.freq)

        # Tones
        ((txmode, txtone, txpol), (rxmode, rxtone, rxpol)) = \
            chirp_common.split_tone_encode(mem)
        raw[10], raw[11] = _encode_tone(txmode, txtone, txpol)
        raw[8], raw[9] = _encode_tone(rxmode, rxtone, rxpol)

        # Byte 16
        power_idx = self.POWER_LEVELS.index(mem.power) if mem.power else 0
        f16 = (power_idx & 0x03) << 6
        if mem.mode == 'NFM':
            f16 |= 0x10
        # offset dir
        _offsetdir_map = {'': 0, '+': 1, '-': 2, 'split': 3, 'off': 0}
        f16 |= (_offsetdir_map.get(mem.duplex, 0) & 0x03) << 2

        f17 = f18 = f19 = f20 = 0
        if mem.extra:
            for rs in mem.extra:
                nm = rs.get_name()
                v = rs.value
                if nm == 'busylock':
                    f19 |= (int(v) & 0x03) << 6
                elif nm == 'txdis':
                    f19 |= (0x20 if bool(v) else 0)
                elif nm == 'talkaround':
                    f16 |= (1 if bool(v) else 0)
                elif nm == 'freqinvert':
                    f16 |= (0x02 if bool(v) else 0)
                elif nm == 'compand':
                    f20 |= (0x20 if bool(v) else 0)
                elif nm == 'scram':
                    f20 |= (0x10 if bool(v) else 0)
                elif nm == 'cepin24bit':
                    f20 |= (0x80 if bool(v) else 0)
                elif nm == 'cepindcs':
                    f20 |= (0x40 if bool(v) else 0)
                elif nm == 'signaltype':
                    f18 |= (int(v) & 0x07) << 5
                elif nm == 'sqtype':
                    f17 |= (int(v) & 0x0F)
                elif nm == 'fivetoneptt':
                    f17 |= (int(v) & 0x03) << 6
                elif nm == 'dtmfptt':
                    f17 |= (int(v) & 0x03) << 4
                elif nm == 'jumpfreq':
                    f18 |= (int(v) & 0x03)
                elif nm == 'freqstep':
                    raw[24] = int(v) & 0xFF
                elif nm == 'dtmfidx':
                    raw[25] = int(v) & 0xFF
                elif nm == 'twotoneidx':
                    raw[26] = int(v) & 0xFF
                elif nm == 'fivetoneidx':
                    raw[27] = int(v) & 0xFF
                elif nm == 'mdcidx':
                    raw[28] = int(v) & 0xFF
                elif nm == 'scanlist':
                    raw[29] = int(v) & 0xFF
                elif nm == 'emerglist':
                    raw[30] = int(v) & 0xFF

        raw[16] = f16
        raw[17] = f17
        raw[18] = f18
        raw[19] = f19
        raw[20] = f20

        # Name — truncate to LENGTH_NAME chars before encoding so we never
        # store more than the radio can display, regardless of what the UI passed.
        enc_name = _encode_name(mem.name[:self.LENGTH_NAME], 16)
        raw[32:48] = enc_name

        _write_chn_raw(mmap, idx, bytes(raw))
        _set_chn_used(mmap, idx, True)

        # Scan skip flag
        addr = ADDR_SCAN_FLAGS + idx // 8
        bv = _mb(mmap, addr)
        if mem.skip == 'S':
            bv |= (1 << (idx % 8))
        else:
            bv &= ~(1 << (idx % 8))
        _mwb(mmap, addr, bv)

    # ── Settings helpers ────────────────────────────────────────────────────

    def _s(self, offset):
        return _mb(self._mmap, ADDR_SETTINGS + offset)

    def _sw(self, offset, value):
        _mwb(self._mmap, ADDR_SETTINGS + offset, value)

    def _sr(self, offset, n):
        return _mread(self._mmap, ADDR_SETTINGS + offset, n)

    # ── get_settings ────────────────────────────────────────────────────────

    def get_settings(self):
        s = [self._s(i) for i in range(128)]

        # Pre-read zone names so they can be used in selectors elsewhere
        _zone_labels = []
        for _zi in range(10):
            _zbase = ADDR_ZONES + _zi * 152
            _zraw = _mread(self._mmap, _zbase + 136, 16)
            _zname = _decode_name(_zraw).strip()
            _zone_labels.append(
                'Zone %d: %s' % (_zi + 1, _zname) if _zname
                else 'Zone %d' % (_zi + 1))

        basic = RadioSettingGroup('basic', 'Basic Settings')
        display = RadioSettingGroup('display', 'Display')
        keys = RadioSettingGroup('keys', 'Key Assignments')
        vfo_a = RadioSettingGroup('vfo_a', 'VFO A')
        vfo_b = RadioSettingGroup('vfo_b', 'VFO B')
        zones = RadioSettingGroup('zones', 'Zones')
        scan = RadioSettingGroup('scan', 'Scan')
        dtmf = RadioSettingGroup('dtmf', 'DTMF')
        twotone = RadioSettingGroup('twotone', '2-Tone')
        fivetone = RadioSettingGroup('fivetone', '5-Tone')
        mdc = RadioSettingGroup('mdc', 'MDC-1200')
        emerg = RadioSettingGroup('emerg', 'Emergency')
        aprs = RadioSettingGroup('aprs', 'APRS')
        gps = RadioSettingGroup('gps', 'GPS')
        gps_book = RadioSettingGroup('gps_book', 'GPS Book')
        boot = RadioSettingGroup('boot', 'Boot Screen')

        top = RadioSettings(basic, display, keys, vfo_a, vfo_b, zones, scan,
                            dtmf, twotone, fivetone, mdc, emerg, aprs,
                            gps, gps_book, boot)

        def _add(group, path, label, val_obj):
            group.append(RadioSetting(path, label, val_obj))

        # ── Basic ────────────────────────────────────────────────────────────
        _add(basic, 'settings.chaworkmode', 'Channel A Work Mode',
             RadioSettingValueList(LIST_WORKMODE, current_index=min(s[0], 1)))
        _add(basic, 'settings.chbworkmode', 'Channel B Work Mode',
             RadioSettingValueList(LIST_WORKMODE, current_index=min(s[1], 1)))

        cha_num = (s[2] << 8) | s[3]
        chb_num = (s[4] << 8) | s[5]
        _add(basic, 'settings.chanum', 'Channel A Number',
             RadioSettingValueInteger(
                 1, _MAX_CHN, max(1, min(cha_num, _MAX_CHN))))
        _add(basic, 'settings.chbnum', 'Channel B Number',
             RadioSettingValueInteger(
                 1, _MAX_CHN, max(1, min(chb_num, _MAX_CHN))))

        _add(basic, 'settings.chazone', 'Channel A Active Zone',
             RadioSettingValueList(_zone_labels,
                                   current_index=min(s[6], 9)))
        _add(basic, 'settings.chbzone', 'Channel B Active Zone',
             RadioSettingValueList(_zone_labels,
                                   current_index=min(s[7], 9)))

        blight_idx = 0 if s[8] < 5 else min(s[8] - 4, 26)
        _add(basic, 'settings.backlight', 'Backlight Time',
             RadioSettingValueList(LIST_BACKLIGHT,
                                   current_index=blight_idx))
        _add(basic, 'settings.blightlv', 'Backlight Level',
             RadioSettingValueList(LIST_BLIGHT_LV,
                                   current_index=max(0, min(s[9] - 1, 4))))

        _add(basic, 'settings.dualmode', 'Dual Standby',
             RadioSettingValueBoolean(bool(s[11])))
        _add(basic, 'settings.mainband', 'Main Band',
             RadioSettingValueList(LIST_MAIN_BAND,
                                   current_index=min(s[12], 1)))
        _add(basic, 'settings.squelch', 'Squelch',
             RadioSettingValueList(LIST_SQUELCH, current_index=min(s[13], 9)))

        vox_raw = s[14]
        _add(basic, 'settings.voxlv', 'VOX Level (0=off)',
             RadioSettingValueInteger(0, 9, max(0, min(vox_raw - 1, 9))))

        voxdly_idx = max(0, min((s[15] - 10) // 5, len(LIST_VOX_DLY) - 1))
        _add(basic, 'settings.voxdettime', 'VOX Delay',
             RadioSettingValueList(LIST_VOX_DLY, current_index=voxdly_idx))

        _add(basic, 'settings.posave', 'Power Save',
             RadioSettingValueList(LIST_POSAVE, current_index=min(s[16], 3)))
        _add(basic, 'settings.posavedly', 'Power Save Delay',
             RadioSettingValueList(LIST_POSAVE_DLY,
                                   current_index=min(s[17], 4)))

        apo_idx = min(s[20], len(LIST_APO) - 1)
        _add(basic, 'settings.apo', 'Auto Power Off',
             RadioSettingValueList(LIST_APO, current_index=apo_idx))

        tot_idx = min(s[21], len(LIST_TOT) - 1)
        _add(basic, 'settings.tot', 'TX Timeout Timer',
             RadioSettingValueList(LIST_TOT, current_index=tot_idx))

        _add(basic, 'settings.pretot', 'Pre-TX Alarm (s)',
             RadioSettingValueInteger(0, 10, min(s[22], 10)))

        _add(basic, 'settings.hz1750', '1750 Hz Tone Freq',
             RadioSettingValueList(LIST_HZ1750, current_index=min(s[26], 3)))

        _add(basic, 'settings.noaach', 'NOAA Channel',
             RadioSettingValueList(LIST_NOAA_CH, current_index=min(s[30], 9)))

        _add(basic, 'settings.loneworktim', 'Lone Worker Timer (min)',
             RadioSettingValueInteger(0, 99, s[18]))
        _add(basic, 'settings.loneworkrsp', 'Lone Worker Response',
             RadioSettingValueList(LIST_LONEWORK_RSP,
                                   current_index=min(s[19], 3)))

        # b32 packed
        b32 = s[32]
        _add(basic, 'settings.voxsw', 'VOX Switch',
             RadioSettingValueBoolean(bool((b32 >> 7) & 1)))
        _add(basic, 'settings.aprsw', 'APRS Switch',
             RadioSettingValueBoolean(bool((b32 >> 6) & 1)))
        _add(basic, 'settings.lonework', 'Lone Worker Enable',
             RadioSettingValueBoolean(bool((b32 >> 5) & 1)))
        _add(basic, 'settings.daodi', 'CTCSS/DCS Save Both',
             RadioSettingValueBoolean(bool((b32 >> 4) & 1)))
        _add(basic, 'settings.voice', 'Voice Prompt',
             RadioSettingValueList(LIST_VOICE,
                                   current_index=min((b32 >> 2) & 0x03, 2)))
        _add(basic, 'settings.busylockglobal', 'Busy Channel Lockout',
             RadioSettingValueBoolean(bool(b32 & 0x03)))

        b33 = s[33]
        _add(basic, 'settings.keylock', 'Key Lock',
             RadioSettingValueBoolean(bool((b33 >> 7) & 1)))
        _add(basic, 'settings.autokey', 'Auto Key Lock',
             RadioSettingValueBoolean(bool((b33 >> 6) & 1)))

        b34 = s[34]
        _add(basic, 'settings.beep', 'Beep Tone',
             RadioSettingValueBoolean(bool((b34 >> 7) & 1)))
        _add(basic, 'settings.endtone', 'End Tone',
             RadioSettingValueList(LIST_END_TONE,
                                   current_index=min((b34 >> 5) & 0x03, 3)))

        b37 = s[37]
        _add(basic, 'settings.reord', 'Record Enable',
             RadioSettingValueBoolean(bool((b37 >> 7) & 1)))
        _add(basic, 'settings.recordmode', 'Record Mode',
             RadioSettingValueList(LIST_RECORD_MODE,
                                   current_index=min((b37 >> 5) & 0x03, 2)))
        _add(basic, 'settings.tianqi', 'Weather Alarm',
             RadioSettingValueBoolean(bool((b37 >> 3) & 1)))
        _add(basic, 'settings.langsel', 'Language',
             RadioSettingValueList(['English', 'Chinese'],
                                   current_index=(b37 >> 2) & 1))
        _add(basic, 'settings.pownface', 'Power-On Screen',
             RadioSettingValueList(LIST_POWON_FACE,
                                   current_index=min(b37 & 0x03, 2)))

        b38 = s[38]
        _add(basic, 'settings.tailfreq', 'Tail Tone Freq',
             RadioSettingValueList(LIST_TAIL_FREQ,
                                   current_index=min((b38 >> 5) & 0x07, 4)))
        _add(basic, 'settings.noaa', 'NOAA Weather',
             RadioSettingValueBoolean(bool((b38 >> 4) & 1)))
        _add(basic, 'settings.dispdir', 'Call Direction Display',
             RadioSettingValueBoolean(bool((b38 >> 3) & 1)))
        _add(basic, 'settings.fminter', 'FM Radio',
             RadioSettingValueBoolean(bool((b38 >> 2) & 1)))
        _add(basic, 'settings.noisecancel', 'Noise Cancel',
             RadioSettingValueBoolean(bool((b38 >> 1) & 1)))
        _add(basic, 'settings.enhancefunc', 'Enhance Function',
             RadioSettingValueBoolean(bool(b38 & 1)))

        _add(basic, 'settings.gpszone', 'GPS Zone',
             RadioSettingValueInteger(0, 9, min(s[24], 9)))
        _add(basic, 'settings.gpsid', 'GPS ID Channel',
             RadioSettingValueInteger(0, 255, s[31]))

        # Passwords
        pow_pwd = bytes(s[64 + i] for i in range(8)
                        if s[64 + i] not in (0xFF, 0))
        pow_pwd = ''.join(chr(b) for b in bytes(
            s[64 + i] for i in range(8)) if b not in (0, 0xFF))[:8]
        _add(basic, 'settings.powpassword', 'Power-On Password',
             RadioSettingValueString(0, 8, pow_pwd, False,
                                     chirp_common.CHARSET_ASCII))
        wr_pwd = ''.join(chr(b) for b in bytes(
            s[72 + i] for i in range(8)) if b not in (0, 0xFF))[:8]
        _add(basic, 'settings.wrpassword', 'Write Password',
             RadioSettingValueString(0, 8, wr_pwd, False,
                                     chirp_common.CHARSET_ASCII))

        radio_name = _decode_name(bytes(s[80:96]))
        _add(basic, 'settings.radioname', 'Radio Name',
             RadioSettingValueString(0, 8, radio_name, False, _CHARSET))

        # ── Display ──────────────────────────────────────────────────────────
        b10 = s[10]
        _add(display, 'settings.chadispmode', 'Channel A Display Mode',
             RadioSettingValueList(LIST_DISP_MODE,
                                   current_index=min((b10 >> 4) & 0x0F, 3)))
        _add(display, 'settings.chbdispmode', 'Channel B Display Mode',
             RadioSettingValueList(LIST_DISP_MODE,
                                   current_index=min(b10 & 0x0F, 3)))

        # ── Key Assignments ──────────────────────────────────────────────────
        key_names = [
            ('settings.skey1', 'Side Key 1 (short)'),
            ('settings.skey2', 'Side Key 2 (short)'),
            ('settings.lkey1', 'Side Key 1 (long)'),
            ('settings.lkey2', 'Side Key 2 (long)'),
            ('settings.skey3', 'Side Key 3 (short)'),
            ('settings.skey4', 'Side Key 4 (short)'),
            ('settings.lkey3', 'Side Key 3 (long)'),
            ('settings.lkey4', 'Side Key 4 (long)'),
        ]
        raw_keys = [s[48], s[49], s[50], s[51], s[52], s[53], s[54], s[55]]
        for (path, label), raw_val in zip(key_names, raw_keys):
            idx_v = min(raw_val, len(LIST_KEY_FUNC) - 1)
            _add(keys, path, label,
                 RadioSettingValueList(LIST_KEY_FUNC, current_index=idx_v))

        # ── VFO A ────────────────────────────────────────────────────────────
        self._add_vfo_settings(vfo_a, 0)

        # ── VFO B ────────────────────────────────────────────────────────────
        self._add_vfo_settings(vfo_b, 1)

        # ── Zones ────────────────────────────────────────────────────────────
        zone_cnt = _mb(self._mmap, ADDR_ZONE_CNT)
        _add(zones, 'zones.count', 'Zone Count',
             RadioSettingValueInteger(0, 10, min(zone_cnt, 10)))
        for zi in range(10):
            base = ADDR_ZONES + zi * 152
            raw_name = _mread(self._mmap, base + 136, 16)
            zname = _decode_name(raw_name)
            chn_num = min(_mb(self._mmap, base), 67)
            chn_ids = []
            for j in range(chn_num):
                hi = _mb(self._mmap, base + 2 + j * 2)
                lo = _mb(self._mmap, base + 3 + j * 2)
                cid = (hi << 8) | lo
                if 1 <= cid <= _MAX_CHN:
                    chn_ids.append(str(cid))
            _add(zones, 'zones.zone%d_name' % zi, 'Zone %d Name' % (zi + 1),
                 RadioSettingValueString(0, 8, zname, False, _CHARSET))
            chn_str = ','.join(chn_ids)
            _add(zones, 'zones.zone%d_chns' % zi,
                 'Zone %d Channels — up to 64, enter comma-sep IDs' % (zi + 1),
                 RadioSettingValueString(0, 200, chn_str, False,
                                         chirp_common.CHARSET_ASCII + ','))
            # Read-only preview: show channel names for the first 12 entries
            _preview_parts = []
            for _cid_str in chn_ids[:12]:
                try:
                    _cid = int(_cid_str)
                    if _chn_used(self._mmap, _cid - 1):
                        _craw = _read_chn_raw(self._mmap, _cid - 1)
                        _cname = _decode_name(_craw[32:48]).strip()
                        _preview_parts.append(
                            '%d:%s' % (_cid, _cname) if _cname
                            else _cid_str)
                    else:
                        _preview_parts.append(_cid_str)
                except Exception:
                    _preview_parts.append(_cid_str)
            if len(chn_ids) > 12:
                _preview_parts.append('+%d more' % (len(chn_ids) - 12))
            _preview = (', '.join(_preview_parts)
                        if _preview_parts else '(empty)')
            _add(zones, 'zones.zone%d_preview' % zi,
                 'Zone %d Contents (read-only)' % (zi + 1),
                 RadioSettingValueString(0, 200, _preview, False,
                                         chirp_common.CHARSET_ASCII + ',:+'))

        # ── Scan ─────────────────────────────────────────────────────────────
        for si in range(10):
            base = ADDR_SCAN_FREQ + si * 8
            up_raw = _mread(self._mmap, base, 4)
            dw_raw = _mread(self._mmap, base + 4, 4)
            up_hz = min(520_000_000, _decode_freq_le(up_raw))
            dw_hz = min(520_000_000, _decode_freq_le(dw_raw))
            _add(scan, 'scan.freq%d_up' % si,
                 'Scan %d Up Freq (Hz)' % (si + 1),
                 RadioSettingValueInteger(0, 520_000_000, up_hz))
            _add(scan, 'scan.freq%d_dw' % si,
                 'Scan %d Down Freq (Hz)' % (si + 1),
                 RadioSettingValueInteger(0, 520_000_000, dw_hz))

        sp = _mread(self._mmap, ADDR_SCAN_PARA, 9)
        _add(scan, 'scan.scanmode', 'Scan Mode',
             RadioSettingValueList(LIST_SCAN_MODE,
                                   current_index=min(sp[0], 2)))
        _add(scan, 'scan.backscantim', 'Back Scan Time (s)',
             RadioSettingValueInteger(0, 250,
                                      max(0, sp[1] - 5) if sp[1] > 5 else 0))
        _add(scan, 'scan.rxresume', 'RX Resume (s)',
             RadioSettingValueInteger(0, 254,
                                      max(0, sp[2] - 1) if sp[2] > 1 else 0))
        _add(scan, 'scan.txresume', 'TX Resume (s)',
             RadioSettingValueInteger(0, 254,
                                      max(0, sp[3] - 1) if sp[3] > 1 else 0))
        _add(scan, 'scan.rtnchtype', 'Return Channel Type',
             RadioSettingValueList(LIST_RTNCH, current_index=min(sp[4], 2)))
        _add(scan, 'scan.prioscan', 'Priority Scan',
             RadioSettingValueBoolean(bool(sp[5])))
        prio_ch = (sp[6] << 8) | sp[7]
        _add(scan, 'scan.priochannel', 'Priority Channel',
             RadioSettingValueInteger(
                 1, _MAX_CHN, max(1, min(prio_ch, _MAX_CHN))))
        _add(scan, 'scan.scanrange', 'Scan Range',
             RadioSettingValueInteger(0, 255, sp[8]))

        # ── DTMF ─────────────────────────────────────────────────────────────
        dp = _mread(self._mmap, ADDR_DTMF, 88)
        _add(dtmf, 'dtmf.dtmfsw', 'DTMF Switch',
             RadioSettingValueBoolean(bool(dp[0])))
        _add(dtmf, 'dtmf.codespeed', 'Code Speed',
             RadioSettingValueInteger(0, 9, min(dp[1], 9)))
        _add(dtmf, 'dtmf.firstcodetim', 'First Code Time (ms)',
             RadioSettingValueInteger(0, 2500, dp[2] * 10))
        _add(dtmf, 'dtmf.pretime', 'Pre Time (ms)',
             RadioSettingValueInteger(0, 2500, dp[3] * 10))
        _add(dtmf, 'dtmf.codedly', 'Code Delay (ms)',
             RadioSettingValueInteger(0, 2500, dp[4] * 10))
        _add(dtmf, 'dtmf.pttidpause', 'PTT ID Pause',
             RadioSettingValueInteger(0, 9, min(dp[5], 9)))
        _add(dtmf, 'dtmf.dtmftone', 'DTMF Tone',
             RadioSettingValueBoolean(bool(dp[6])))
        _add(dtmf, 'dtmf.resettime', 'Reset Time',
             RadioSettingValueInteger(
                 0, 50, max(0, dp[7] - 10) if dp[7] >= 10 else 0))
        # Sep/Grp codes stored as raw nibble +10
        sep_raw = dp[8]
        sep_val = sep_raw - 10 if sep_raw >= 10 else 0
        _add(dtmf, 'dtmf.sepcode', 'Sep Code (0-9)',
             RadioSettingValueInteger(0, 9, min(sep_val, 9)))
        grp_raw = dp[9]
        grp_val = grp_raw - 9 if grp_raw not in (0, 0xFF) else 0
        _add(dtmf, 'dtmf.grpcode', 'Group Code (0=none)',
             RadioSettingValueInteger(0, 9, max(0, min(grp_val, 9))))
        _add(dtmf, 'dtmf.decrsp', 'Decode Response',
             RadioSettingValueInteger(0, 9, min(dp[10], 9)))
        _add(dtmf, 'dtmf.did', 'Unit ID',
             RadioSettingValueString(0, 3, _decode_dtmf_bytes(dp[16:19], 3),
                                     False, chirp_common.CHARSET_ASCII))
        _add(dtmf, 'dtmf.bot', 'BOT Code',
             RadioSettingValueString(0, 16, _decode_dtmf_bytes(dp[24:40]),
                                     False, chirp_common.CHARSET_ASCII))
        _add(dtmf, 'dtmf.eot', 'EOT Code',
             RadioSettingValueString(0, 16, _decode_dtmf_bytes(dp[40:56]),
                                     False, chirp_common.CHARSET_ASCII))
        _add(dtmf, 'dtmf.stun', 'Stun Code',
             RadioSettingValueString(0, 16, _decode_dtmf_bytes(dp[56:72]),
                                     False, chirp_common.CHARSET_ASCII))
        _add(dtmf, 'dtmf.kill', 'Kill Code',
             RadioSettingValueString(0, 16, _decode_dtmf_bytes(dp[72:88]),
                                     False, chirp_common.CHARSET_ASCII))
        # DTMF encode flags (LE u16, inverted)
        flags_raw = _mread(self._mmap, ADDR_DTMF_FLAGS, 2)
        use_flg = ~((flags_raw[1] << 8) | flags_raw[0]) & 0xFFFF
        for di in range(16):
            enc_data = _mread(self._mmap, ADDR_DTMF_ENC + di * 16, 16)
            enc_str = _decode_dtmf_bytes(enc_data) if (
                use_flg >> di) & 1 else ''
            _add(dtmf, 'dtmf_enc.%d' % di, 'DTMF Encode %d' % (di + 1),
                 RadioSettingValueString(0, 16, enc_str, False,
                                         chirp_common.CHARSET_ASCII))
            _add(dtmf, 'dtmf_enc_en.%d' % di,
                 'DTMF Encode %d Enable' % (di + 1),
                 RadioSettingValueBoolean(bool((use_flg >> di) & 1)))

        # ── 2-Tone ───────────────────────────────────────────────────────────
        tp = _mread(self._mmap, ADDR_2TONE, 8)
        _add(twotone, 'twotone.firsttone', 'First Tone Duration',
             RadioSettingValueInteger(0, 50, max(0, tp[0] // 5 - 1)))
        _add(twotone, 'twotone.secondtone', 'Second Tone Duration',
             RadioSettingValueInteger(0, 50, max(0, tp[1] // 5 - 1)))
        _add(twotone, 'twotone.tonedur', 'Tone Duration',
             RadioSettingValueInteger(0, 50, max(0, tp[2] // 5 - 1)))
        _add(twotone, 'twotone.toneint', 'Tone Interval',
             RadioSettingValueInteger(0, 255, tp[3]))
        _add(twotone, 'twotone.stonesw', '2-Tone Switch',
             RadioSettingValueBoolean(bool(tp[4])))
        for ti in range(16):
            base = ADDR_2TONE_ENC + ti * 16
            ep = _mread(self._mmap, base, 16)
            f1 = (ep[0] << 8) | ep[1]
            f2 = (ep[2] << 8) | ep[3]
            tname_raw = bytes(ep[4:16])
            tname = tname_raw.split(b'\x00')[0].decode(
                'ascii', errors='replace')
            f1_v = f1 if 288 <= f1 <= 3116 else 0
            f2_v = f2 if 288 <= f2 <= 3116 else 0
            _add(twotone, 'twotone_enc.%d_f1' % ti,
                 '2-Tone %d Freq1 (Hz)' % (ti + 1),
                 RadioSettingValueInteger(0, 3116, f1_v))
            _add(twotone, 'twotone_enc.%d_f2' % ti,
                 '2-Tone %d Freq2 (Hz)' % (ti + 1),
                 RadioSettingValueInteger(0, 3116, f2_v))
            _add(twotone, 'twotone_enc.%d_name' % ti,
                 '2-Tone %d Name' % (ti + 1),
                 RadioSettingValueString(0, 12, tname[:12], False,
                                         chirp_common.CHARSET_ASCII))
        # 2-Tone decode params
        td = _mread(self._mmap, ADDR_2TONE_DEC, 16)
        _add(twotone, 'twotone.decodersp', 'Decode Response',
             RadioSettingValueList(LIST_2TONE_DEC_RSP,
                                   current_index=min(td[0], 2)))
        _add(twotone, 'twotone.resetim', 'Reset Time',
             RadioSettingValueInteger(
                 0, 50, max(0, td[1] - 10) if td[1] >= 10 else 0))
        _add(twotone, 'twotone.decformat', 'Decode Format',
             RadioSettingValueInteger(0, 9, min(td[2], 9)))
        for tidx, tkey in enumerate(['atone', 'btone', 'ctone', 'dtone']):
            fval = (td[4 + tidx * 2] << 8) | td[5 + tidx * 2]
            fval = fval if 288 <= fval <= 3116 else 0
            _add(twotone, 'twotone.%s' % tkey,
                 '2-Tone Dec %s (Hz)' % tkey.upper(),
                 RadioSettingValueInteger(0, 3116, fval))

        # ── 5-Tone ───────────────────────────────────────────────────────────
        # Enable table (13 bytes, inverted bitmap)
        tbl5 = _mread(self._mmap, ADDR_5TONE_TBL, 13)
        # Encode list (100 × 32)
        for fi in range(100):
            base = ADDR_5TONE_ENC + fi * 32
            ep = _mread(self._mmap, base, 32)
            stand = min(ep[0], len(LIST_5TONE_STAND) - 1)
            ct_raw = ep[1]
            ct_idx = min(max(ct_raw - 7, 0), len(LIST_5TONE_CODETIME) - 1)
            code_len = min(ep[2], 24)
            id_str = _decode_5tone_id(bytes(ep[3:23]), code_len)
            scall = min(ep[23], len(LIST_5TONE_SCALL) - 1)
            name_raw = bytes(ep[24:32])
            fname = ''
            for b in name_raw:
                if b == 0 or b > 127:
                    break
                fname += chr(b)
            en_byte = fi // 8
            en_bit = fi % 8
            en_flag = ((tbl5[en_byte] >> en_bit) & 1) == 0
            _add(fivetone, 'fivetone_enc.%d_stand' % fi,
                 '5-Tone %d Standard' % (fi + 1),
                 RadioSettingValueList(LIST_5TONE_STAND, current_index=stand))
            _add(fivetone, 'fivetone_enc.%d_codetime' % fi,
                 '5-Tone %d Code Time' % (fi + 1),
                 RadioSettingValueList(LIST_5TONE_CODETIME,
                                       current_index=ct_idx))
            _add(fivetone, 'fivetone_enc.%d_codelen' % fi,
                 '5-Tone %d Code Length' % (fi + 1),
                 RadioSettingValueInteger(0, 24, code_len))
            _add(fivetone, 'fivetone_enc.%d_id' % fi,
                 '5-Tone %d Code IDs' % (fi + 1),
                 RadioSettingValueString(0, 40, id_str, False,
                                         chirp_common.CHARSET_ASCII))
            _add(fivetone, 'fivetone_enc.%d_scall' % fi,
                 '5-Tone %d Special Call' % (fi + 1),
                 RadioSettingValueList(LIST_5TONE_SCALL, current_index=scall))
            _add(fivetone, 'fivetone_enc.%d_name' % fi,
                 '5-Tone %d Name' % (fi + 1),
                 RadioSettingValueString(0, 8, fname[:8], False,
                                         chirp_common.CHARSET_ASCII))
            _add(fivetone, 'fivetone_enc.%d_en' % fi,
                 '5-Tone %d Enable' % (fi + 1),
                 RadioSettingValueBoolean(en_flag))

        # 5-Tone decode params
        fd = _mread(self._mmap, ADDR_5TONE_DEC, 24)
        _add(fivetone, 'fivetone.decrsp', 'Decode Response',
             RadioSettingValueInteger(0, 9, min(fd[0], 9)))
        _add(fivetone, 'fivetone.decstand', 'Decode Standard',
             RadioSettingValueList(LIST_5TONE_STAND,
                                   current_index=min(fd[1], 13)))
        _add(fivetone, 'fivetone.dectim', 'Tone Time',
             RadioSettingValueInteger(0, 50, max(0, fd[2] - 7)))
        _add(fivetone, 'fivetone.pretime', 'Pre Time (ms)',
             RadioSettingValueInteger(0, 2500, fd[11] * 10))
        _add(fivetone, 'fivetone.codedly', 'Code Delay (ms)',
             RadioSettingValueInteger(0, 2500, fd[12] * 10))
        _add(fivetone, 'fivetone.resettime', 'Reset Time',
             RadioSettingValueInteger(
                 0, 50, max(0, fd[14] - 10) if fd[14] >= 10 else 0))
        _add(fivetone, 'fivetone.fiveani', 'ANI',
             RadioSettingValueBoolean(bool(fd[16])))

        # ── MDC-1200 ─────────────────────────────────────────────────────────
        # 5 system params
        for mi in range(5):
            base = ADDR_MDC_PARA + mi * 8
            mp = _mread(self._mmap, base, 8)
            ctrl = (mp[0] >> 7) & 1
            dec_tone = (mp[0] >> 6) & 1
            enc_id = (mp[1] << 8) | mp[2]
            _add(mdc, 'mdc_para.%d_ctrl' % mi,
                 'MDC Sys %d Control' % (mi + 1),
                 RadioSettingValueBoolean(bool(ctrl)))
            _add(mdc, 'mdc_para.%d_dectone' % mi,
                 'MDC Sys %d Dec Tone' % (mi + 1),
                 RadioSettingValueBoolean(bool(dec_tone)))
            _add(mdc, 'mdc_para.%d_encid' % mi,
                 'MDC Sys %d Enc ID',
                 RadioSettingValueInteger(0, 9999, enc_id))

        # BIIS params
        biis = _mread(self._mmap, ADDR_MDC_BIIS, 9)
        _add(mdc, 'mdc.selfid', 'BIIS Self ID',
             RadioSettingValueInteger(0, 65535, (biis[0] << 8) | biis[1]))
        _add(mdc, 'mdc.grpid', 'BIIS Group ID',
             RadioSettingValueInteger(0, 65535, (biis[2] << 8) | biis[3]))
        _add(mdc, 'mdc.tonesw', 'BIIS Tone Switch',
             RadioSettingValueBoolean(bool(biis[8])))

        # MDC decode list (100 × 16)
        tbl_mdc = _mread(self._mmap, ADDR_MDC_TBL, 16)
        for mi in range(100):
            base = ADDR_MDC_DEC + mi * 16
            mp = _mread(self._mmap, base, 16)
            dec_id = min(9999, (mp[0] << 8) | mp[1])
            mname = _decode_name(bytes(mp[4:16]))
            en_byte = mi // 8
            en_bit = mi % 8
            en_flag = ((tbl_mdc[en_byte] >> en_bit) & 1) == 0
            _add(mdc, 'mdc_dec.%d_id' % mi,
                 'MDC Dec %d ID' % (mi + 1),
                 RadioSettingValueString(0, 4, '%04d' % dec_id, False,
                                         chirp_common.CHARSET_ASCII))
            _add(mdc, 'mdc_dec.%d_name' % mi,
                 'MDC Dec %d Name' % (mi + 1),
                 RadioSettingValueString(0, 8, mname[:8], False, _CHARSET))
            _add(mdc, 'mdc_dec.%d_en' % mi,
                 'MDC Dec %d Enable' % (mi + 1),
                 RadioSettingValueBoolean(en_flag))

        # ── Emergency ────────────────────────────────────────────────────────
        for ei in range(10):
            base = ADDR_EMERG + ei * 16
            ep = _mread(self._mmap, base, 16)
            _add(emerg, 'emerg.%d_dur' % ei,
                 'Emerg %d Duration' % (ei + 1),
                 RadioSettingValueInteger(0, 255, ep[0]))
            _add(emerg, 'emerg.%d_chsel' % ei,
                 'Emerg %d Ch Select' % (ei + 1),
                 RadioSettingValueInteger(0, 9, min(ep[1], 9)))
            _add(emerg, 'emerg.%d_rxtime' % ei,
                 'Emerg %d RX Time' % (ei + 1),
                 RadioSettingValueInteger(0, 255, ep[2]))
            _add(emerg, 'emerg.%d_txtime' % ei,
                 'Emerg %d TX Time' % (ei + 1),
                 RadioSettingValueInteger(0, 255, ep[3]))
            _add(emerg, 'emerg.%d_exgtime' % ei,
                 'Emerg %d Exchange Time' % (ei + 1),
                 RadioSettingValueInteger(0, 255, ep[4]))
            _add(emerg, 'emerg.%d_grpno' % ei,
                 'Emerg %d Group Number' % (ei + 1),
                 RadioSettingValueInteger(0, 255, ep[5]))
            _add(emerg, 'emerg.%d_mode' % ei,
                 'Emerg %d Mode' % (ei + 1),
                 RadioSettingValueList(LIST_EMERG_MODE,
                                       current_index=min(ep[6], 3)))
            _add(emerg, 'emerg.%d_type' % ei,
                 'Emerg %d Type' % (ei + 1),
                 RadioSettingValueList(LIST_EMERG_TYPE,
                                       current_index=min(ep[7], 2)))
            _add(emerg, 'emerg.%d_chn' % ei,
                 'Emerg %d Channel' % (ei + 1),
                 RadioSettingValueInteger(
                     1, _MAX_CHN, max(1, min(ep[14], _MAX_CHN))))
            _add(emerg, 'emerg.%d_zone' % ei,
                 'Emerg %d Zone' % (ei + 1),
                 RadioSettingValueInteger(0, 9, min(ep[15], 9)))

        # ── APRS ─────────────────────────────────────────────────────────────
        ap = _mread(self._mmap, ADDR_APRS, 456)
        desno = bytes(ap[0:6]).rstrip(
            b'\xFF\x00\x20').decode('ascii', errors='replace')
        srcno = bytes(ap[8:14]).rstrip(
            b'\xFF\x00\x20').decode('ascii', errors='replace')
        _add(aprs, 'aprs.desno', 'Destination Callsign',
             RadioSettingValueString(0, 6, desno[:6], False,
                                     chirp_common.CHARSET_ASCII))
        _add(aprs, 'aprs.desid', 'Destination SSID',
             RadioSettingValueInteger(0, 15, min(ap[6], 15)))
        _add(aprs, 'aprs.srcno', 'Source Callsign',
             RadioSettingValueString(0, 6, srcno[:6], False,
                                     chirp_common.CHARSET_ASCII))
        _add(aprs, 'aprs.srcid', 'Source SSID',
             RadioSettingValueInteger(0, 15, min(ap[14], 15)))

        b7 = ap[7]
        _add(aprs, 'aprs.passall', 'RX Filter: Pass All',
             RadioSettingValueBoolean(bool((b7 >> 7) & 1)))
        _add(aprs, 'aprs.position', 'RX Filter: Position',
             RadioSettingValueBoolean(bool((b7 >> 6) & 1)))
        _add(aprs, 'aprs.mice', 'RX Filter: Mic-E',
             RadioSettingValueBoolean(bool((b7 >> 5) & 1)))
        _add(aprs, 'aprs.object', 'RX Filter: Object',
             RadioSettingValueBoolean(bool((b7 >> 4) & 1)))
        _add(aprs, 'aprs.item', 'RX Filter: Item',
             RadioSettingValueBoolean(bool((b7 >> 3) & 1)))
        _add(aprs, 'aprs.message', 'RX Filter: Message',
             RadioSettingValueBoolean(bool((b7 >> 2) & 1)))
        _add(aprs, 'aprs.wxreport', 'RX Filter: WX Report',
             RadioSettingValueBoolean(bool((b7 >> 1) & 1)))
        _add(aprs, 'aprs.nmeareport', 'RX Filter: NMEA',
             RadioSettingValueBoolean(bool(b7 & 1)))

        b15 = ap[15]
        _add(aprs, 'aprs.statusreport', 'RX Filter: Status',
             RadioSettingValueBoolean(bool((b15 >> 7) & 1)))
        _add(aprs, 'aprs.other', 'RX Filter: Other',
             RadioSettingValueBoolean(bool((b15 >> 6) & 1)))
        _add(aprs, 'aprs.power', 'TX Power',
             RadioSettingValueList(LIST_APRS_POWER,
                                   current_index=min((b15 >> 4) & 0x03, 2)))
        _add(aprs, 'aprs.band', 'Band',
             RadioSettingValueBoolean(bool((b15 >> 3) & 1)))
        _add(aprs, 'aprs.beeptone', 'Beep Tone',
             RadioSettingValueBoolean(bool((b15 >> 2) & 1)))
        _add(aprs, 'aprs.longdir', 'Longitude Direction (1=West)',
             RadioSettingValueBoolean(bool((b15 >> 1) & 1)))
        _add(aprs, 'aprs.latdir', 'Latitude Direction (1=South)',
             RadioSettingValueBoolean(bool(b15 & 1)))

        _add(aprs, 'aprs.pretime', 'Pre Time',
             RadioSettingValueInteger(0, 255, ap[16]))
        _add(aprs, 'aprs.codedly', 'Code Delay',
             RadioSettingValueInteger(0, 255, ap[17]))
        ctdcs_mode, ctdcs_val, ctdcs_pol = _decode_tone(ap[18], ap[19])
        _add(aprs, 'aprs.ctdcs', 'RX CTCSS/DCS Filter (Off / Hz / DXXXN)',
             RadioSettingValueString(0, 10,
                                     self._tone_to_str(ctdcs_mode, ctdcs_val,
                                                       ctdcs_pol),
                                     False, chirp_common.CHARSET_ASCII))

        b92 = ap[92]
        _add(aprs, 'aprs.beacon', 'Beacon',
             RadioSettingValueBoolean(bool((b92 >> 7) & 1)))
        _add(aprs, 'aprs.heighttype', 'Height Type',
             RadioSettingValueBoolean(bool((b92 >> 6) & 1)))
        _add(aprs, 'aprs.pttid', 'PTT ID',
             RadioSettingValueList(LIST_PTTID,
                                   current_index=min((b92 >> 4) & 0x03, 3)))
        _add(aprs, 'aprs.encodetype', 'Encode Type',
             RadioSettingValueBoolean(bool((b92 >> 3) & 1)))
        _add(aprs, 'aprs.micetype', 'Mic-E Type',
             RadioSettingValueList(LIST_MICETYPE,
                                   current_index=min(b92 & 0x07, 7)))

        _add(aprs, 'aprs.sendinterval', 'Send Interval (s)',
             RadioSettingValueInteger(0, 255, ap[88]))
        _add(aprs, 'aprs.regularlysend', 'Regularly Send',
             RadioSettingValueBoolean(bool(ap[89])))
        _add(aprs, 'aprs.aprsdistime', 'Display Time',
             RadioSettingValueInteger(0, 255, ap[90]))

        txtlen = min(ap[95], 60)
        _add(aprs, 'aprs.txtlength', 'Text Length',
             RadioSettingValueInteger(0, 60, txtlen))
        _valid_aprs = set(chirp_common.CHARSET_ASCII + ' .,!?-+/')
        aprs_txt = ''.join(
            c for c in bytes(ap[108:108 + txtlen]).decode(
                'ascii', errors='replace')
            if c in _valid_aprs)
        _add(aprs, 'aprs.txt', 'APRS Text (max 60)',
             RadioSettingValueString(0, 60, aprs_txt[:60], False,
                                     chirp_common.CHARSET_ASCII + ' .,!?-+/'))

        posicon_tbl = chr(ap[20]) if 32 <= ap[20] <= 126 else '/'
        posicon_sym = chr(ap[21]) if 32 <= ap[21] <= 126 else ' '
        _add(aprs, 'aprs.postable', 'Position Table',
             RadioSettingValueString(0, 1, posicon_tbl, False,
                                     chirp_common.CHARSET_ASCII))
        _add(aprs, 'aprs.posicon', 'Position Icon',
             RadioSettingValueString(0, 1, posicon_sym, False,
                                     chirp_common.CHARSET_ASCII))

        aprs_lon = struct.unpack_from('<i', bytes(ap[96:100]))[0] / 100000.0
        aprs_lat = struct.unpack_from('<i', bytes(ap[100:104]))[0] / 100000.0
        aprs_hgt = struct.unpack_from('<i', bytes(ap[104:108]))[0]
        _add(aprs, 'aprs.lon', 'Longitude (×100000)',
             RadioSettingValueInteger(-18000000, 18000000,
                                      int(aprs_lon * 100000)))
        _add(aprs, 'aprs.lat', 'Latitude (×100000)',
             RadioSettingValueInteger(-9000000, 9000000,
                                      int(aprs_lat * 100000)))
        _add(aprs, 'aprs.height', 'Height (m)',
             RadioSettingValueInteger(0, 99999, max(0, aprs_hgt)))

        # 8 TX callsigns
        for ai in range(8):
            base_a = 24 + ai * 8
            cs = bytes(ap[base_a:base_a + 6]).rstrip(b'\xFF\x00\x20').decode(
                'ascii', errors='replace')
            cs_id = min(ap[base_a + 6], 15) if ap[base_a + 6] <= 15 else 0
            _add(aprs, 'aprs.txcs%d' % ai,
                 'TX Callsign %d' % (ai + 1),
                 RadioSettingValueString(0, 6, cs[:6], False,
                                         chirp_common.CHARSET_ASCII))
            _add(aprs, 'aprs.txcsid%d' % ai,
                 'TX Callsign %d SSID' % (ai + 1),
                 RadioSettingValueInteger(0, 15, cs_id))

        # 32 RX callsigns at ap[200 + i*8]:
        # 6-byte callsign, 1-byte SSID, 1-byte filter flag
        rxcs_count = min(ap[22], 32)
        _add(aprs, 'aprs.rxcscount', 'RX Callsign Count',
             RadioSettingValueInteger(0, 32, rxcs_count))
        for ai in range(32):
            base_r = 200 + ai * 8
            rcs = bytes(ap[base_r:base_r + 6]).rstrip(
                b'\xFF\x00\x20').decode('ascii', errors='replace')
            rcs_id = min(ap[base_r + 6], 15) if ap[base_r + 6] <= 15 else 0
            rcs_filt = bool(ap[base_r + 7])
            _add(aprs, 'aprs.rxcs%d' % ai,
                 'RX Callsign %d' % (ai + 1),
                 RadioSettingValueString(0, 6, rcs[:6], False,
                                         chirp_common.CHARSET_ASCII))
            _add(aprs, 'aprs.rxcsid%d' % ai,
                 'RX Callsign %d SSID' % (ai + 1),
                 RadioSettingValueInteger(0, 15, rcs_id))
            _add(aprs, 'aprs.rxcsfilt%d' % ai,
                 'RX Callsign %d Filter' % (ai + 1),
                 RadioSettingValueBoolean(rcs_filt))

        # 8 APRS TX frequencies (at offset 168 within ap[])
        for ai in range(8):
            freq_raw = bytes(ap[168 + ai * 4:172 + ai * 4])
            freq_hz = _decode_freq_le(freq_raw)
            freq_mhz = '%.4f' % (freq_hz / 1_000_000)
            _add(aprs, 'aprs.txfreq%d' % ai,
                 'APRS TX Freq %d (MHz)' % (ai + 1),
                 RadioSettingValueString(0, 10, freq_mhz, False,
                                         '0123456789.'))

        # ── GPS ──────────────────────────────────────────────────────────────
        b35 = s[35]
        _add(gps, 'settings.gpssw', 'GPS On',
             RadioSettingValueBoolean(bool((b35 >> 7) & 1)))
        _add(gps, 'settings.gpsmode', 'GPS Mode',
             RadioSettingValueList(LIST_GPS_MODE,
                                   current_index=min((b35 >> 5) & 0x03, 2)))
        _add(gps, 'settings.gpsshare', 'GPS Share',
             RadioSettingValueBoolean(bool((b35 >> 4) & 1)))
        _add(gps, 'settings.gpsreq', 'GPS Request',
             RadioSettingValueBoolean(bool((b35 >> 3) & 1)))

        # GPS Book
        gps_flg = _mread(self._mmap, ADDR_GPS_FLAGS, 10)
        for gi in range(80):
            base = ADDR_GPS_BOOK + gi * 16
            gp = _mread(self._mmap, base, 16)
            en_byte = gi // 8
            en_bit = gi % 8
            en_flag = ((gps_flg[en_byte] >> en_bit) & 1) == 0
            code_id = gp[0]
            gname = _decode_name(bytes(gp[2:16]))
            _add(gps_book, 'gps_book.%d_en' % gi,
                 'GPS Book %d Enable' % (gi + 1),
                 RadioSettingValueBoolean(en_flag))
            _add(gps_book, 'gps_book.%d_code' % gi,
                 'GPS Book %d Code ID' % (gi + 1),
                 RadioSettingValueInteger(0, 255, code_id))
            _add(gps_book, 'gps_book.%d_name' % gi,
                 'GPS Book %d Name' % (gi + 1),
                 RadioSettingValueString(0, 7, gname[:7], False, _CHARSET))

        # ── Boot Screen ──────────────────────────────────────────────────────
        if _PIL_AVAILABLE:
            wildcard = ('Image files (*.bmp;*.png;*.jpg;*.jpeg)'
                        '|*.bmp;*.png;*.jpg;*.jpeg'
                        '|BMP files (*.bmp)|*.bmp'
                        '|All files (*.*)|*.*')
            label = ('Boot screen image'
                     ' — auto-scaled to 160×128 (.bmp, .png, .jpg)')
        else:
            wildcard = 'BMP files (*.bmp)|*.bmp|All files (*.*)|*.*'
            label = 'Boot screen image — auto-scaled to 160×128 (.bmp only)'

        bval = RadioSettingValueFile(current=self._boot_image_path,
                                     wildcard=wildcard)
        brs = RadioSetting('boot_screen_image', label, bval)

        def _apply_boot_image(setting, _obj):
            path = str(setting.value).strip()
            self._boot_image_path = path
            if path:
                if not os.path.isfile(path):
                    raise errors.RadioError(
                        'Boot screen image not found: %s' % path)
                self._boot_image_data = _bs_image_to_rgb565(path)
            else:
                self._boot_image_data = None

        brs.set_apply_callback(_apply_boot_image, None)
        boot.append(brs)

        return top

    # ── VFO settings helper ─────────────────────────────────────────────────

    def _add_vfo_settings(self, group, vfo_idx):
        base = ADDR_VFO + vfo_idx * _CHN_SIZE
        raw = _mread(self._mmap, base, _CHN_SIZE)
        prefix = 'vfo_a' if vfo_idx == 0 else 'vfo_b'
        label = 'VFO A' if vfo_idx == 0 else 'VFO B'

        def _add(path, lbl, val_obj):
            group.append(RadioSetting(path, lbl, val_obj))

        rx_hz = min(520_000_000, max(1_000_000, _decode_freq_le(raw[0:4])))
        tx_hz = min(480_000_000, max(1_000_000, _decode_freq_le(raw[4:8])))
        _add('%s.rxfreq' % prefix, '%s RX Freq (Hz)' % label,
             RadioSettingValueInteger(1_000_000, 520_000_000, rx_hz))
        _add('%s.txfreq' % prefix, '%s TX Freq (Hz)' % label,
             RadioSettingValueInteger(1_000_000, 480_000_000, tx_hz))

        tx_mode, tx_val, tx_pol = _decode_tone(raw[10], raw[11])
        rx_mode, rx_val, rx_pol = _decode_tone(raw[8], raw[9])
        tx_tone_str = self._tone_to_str(tx_mode, tx_val, tx_pol)
        rx_tone_str = self._tone_to_str(rx_mode, rx_val, rx_pol)
        _add('%s.txtone' % prefix, '%s TX Tone' % label,
             RadioSettingValueString(0, 10, tx_tone_str, False,
                                     chirp_common.CHARSET_ASCII))
        _add('%s.rxtone' % prefix, '%s RX Tone' % label,
             RadioSettingValueString(0, 10, rx_tone_str, False,
                                     chirp_common.CHARSET_ASCII))

        f16 = raw[16]
        power_idx = (f16 >> 6) & 0x03
        _add('%s.power' % prefix, '%s Power' % label,
             RadioSettingValueList(LIST_POWER,
                                   current_index=min(power_idx, 2)))
        is_narrow = bool((f16 >> 4) & 0x03)
        _add('%s.bandwidth' % prefix, '%s Bandwidth' % label,
             RadioSettingValueList(LIST_BANDWIDTH,
                                   current_index=1 if is_narrow else 0))
        offsetdir = (f16 >> 2) & 0x03
        _add('%s.offsetdir' % prefix, '%s Offset Dir' % label,
             RadioSettingValueList(LIST_OFFSETDIR,
                                   current_index=min(offsetdir, 3)))

        _add('%s.step' % prefix, '%s Freq Step' % label,
             RadioSettingValueInteger(0, 7, raw[24]))

        vfo_name = _decode_name(raw[32:48])
        _add('%s.name' % prefix, '%s Name' % label,
             RadioSettingValueString(0, 8, vfo_name[:8], False, _CHARSET))

    @staticmethod
    def _tone_to_str(mode, val, pol):
        if mode == '':
            return 'Off'
        if mode == 'Tone':
            return '%.1f' % val
        if mode in ('DTCS', 'TSQL'):
            return 'D%03d%s' % (int(val), pol)
        return 'Off'

    @staticmethod
    def _str_to_tone(s):
        s = s.strip()
        if not s or s.upper() == 'OFF':
            return '', 0, 'N'
        if s.upper().startswith('D'):
            code_s = s[1:].rstrip('NI')
            pol = 'R' if s.upper().endswith('I') else 'N'
            try:
                return 'DTCS', int(code_s), pol
            except ValueError:
                return '', 0, 'N'
        try:
            return 'Tone', float(s), 'N'
        except ValueError:
            return '', 0, 'N'

    # ── set_settings ────────────────────────────────────────────────────────

    def set_settings(self, settings):
        for group in settings:
            if isinstance(group, RadioSettingGroup):
                for rs in group:
                    if isinstance(rs, RadioSetting):
                        if rs.has_apply_callback():
                            rs.run_apply_callback()
                        else:
                            self._apply_setting(rs)
            elif isinstance(group, RadioSetting):
                if group.has_apply_callback():
                    group.run_apply_callback()
                else:
                    self._apply_setting(group)

    def _apply_setting(self, rs):  # noqa: C901
        name = rs.get_name()
        val = rs.value

        def _b(n):
            return self._s(n)

        def _wb(n, v):
            self._sw(n, v)

        # ── basic / display / keys ───────────────────────────────────────────
        if name == 'settings.chaworkmode':
            _wb(0, int(val))
        elif name == 'settings.chbworkmode':
            _wb(1, int(val))
        elif name == 'settings.chanum':
            v = int(val)
            _wb(2, (v >> 8) & 0xFF)
            _wb(3, v & 0xFF)
        elif name == 'settings.chbnum':
            v = int(val)
            _wb(4, (v >> 8) & 0xFF)
            _wb(5, v & 0xFF)
        elif name == 'settings.chazone':
            _wb(6, int(val))
        elif name == 'settings.chbzone':
            _wb(7, int(val))
        elif name == 'settings.backlight':
            v = int(val)
            _wb(8, 0 if v == 0 else v + 4)
        elif name == 'settings.blightlv':
            _wb(9, int(val) + 1)
        elif name == 'settings.chadispmode':
            b10 = _b(10)
            _wb(10, (b10 & 0x0F) | ((int(val) & 0x0F) << 4))
        elif name == 'settings.chbdispmode':
            b10 = _b(10)
            _wb(10, (b10 & 0xF0) | (int(val) & 0x0F))
        elif name == 'settings.dualmode':
            _wb(11, 1 if bool(val) else 0)
        elif name == 'settings.mainband':
            _wb(12, int(val))
        elif name == 'settings.squelch':
            _wb(13, int(val))
        elif name == 'settings.voxlv':
            _wb(14, int(val) + 1)
        elif name == 'settings.voxdettime':
            _wb(15, int(val) * 5 + 10)
        elif name == 'settings.posave':
            _wb(16, int(val))
        elif name == 'settings.posavedly':
            _wb(17, int(val))
        elif name == 'settings.hz1750':
            _wb(26, int(val))
        elif name == 'settings.noaach':
            _wb(30, int(val))
        elif name == 'settings.apo':
            _wb(20, int(val))
        elif name == 'settings.tot':
            _wb(21, int(val))
        elif name == 'settings.pretot':
            _wb(22, int(val))
        elif name == 'settings.loneworktim':
            _wb(18, int(val))
        elif name == 'settings.loneworkrsp':
            _wb(19, int(val))
        elif name == 'settings.gpszone':
            _wb(24, int(val))
        elif name == 'settings.gpsid':
            _wb(31, int(val))
        elif name in ('settings.voxsw', 'settings.aprsw',
                      'settings.lonework', 'settings.daodi',
                      'settings.voice', 'settings.busylockglobal'):
            b32 = _b(32)
            if name == 'settings.voxsw':
                b32 = (b32 & 0x7F) | (0x80 if bool(val) else 0)
            elif name == 'settings.aprsw':
                b32 = (b32 & 0xBF) | (0x40 if bool(val) else 0)
            elif name == 'settings.lonework':
                b32 = (b32 & 0xDF) | (0x20 if bool(val) else 0)
            elif name == 'settings.daodi':
                b32 = (b32 & 0xEF) | (0x10 if bool(val) else 0)
            elif name == 'settings.voice':
                b32 = (b32 & 0xF3) | ((int(val) & 0x03) << 2)
            elif name == 'settings.busylockglobal':
                b32 = (b32 & 0xFC) | (1 if bool(val) else 0)
            _wb(32, b32)
        elif name in ('settings.keylock', 'settings.autokey'):
            b33 = _b(33)
            if name == 'settings.keylock':
                b33 = (b33 & 0x7F) | (0x80 if bool(val) else 0)
            else:
                b33 = (b33 & 0xBF) | (0x40 if bool(val) else 0)
            _wb(33, b33)
        elif name in ('settings.beep', 'settings.endtone'):
            b34 = _b(34)
            if name == 'settings.beep':
                b34 = (b34 & 0x7F) | (0x80 if bool(val) else 0)
            else:
                b34 = (b34 & 0x9F) | ((int(val) & 0x03) << 5)
            _wb(34, b34)
        elif name in ('settings.gpssw', 'settings.gpsmode',
                      'settings.gpsshare', 'settings.gpsreq'):
            b35 = _b(35)
            if name == 'settings.gpssw':
                b35 = (b35 & 0x7F) | (0x80 if bool(val) else 0)
            elif name == 'settings.gpsmode':
                b35 = (b35 & 0x9F) | ((int(val) & 0x03) << 5)
            elif name == 'settings.gpsshare':
                b35 = (b35 & 0xEF) | (0x10 if bool(val) else 0)
            elif name == 'settings.gpsreq':
                b35 = (b35 & 0xF7) | (0x08 if bool(val) else 0)
            _wb(35, b35)
        elif name in ('settings.reord', 'settings.recordmode',
                      'settings.tianqi', 'settings.langsel',
                      'settings.pownface'):
            b37 = _b(37)
            if name == 'settings.reord':
                b37 = (b37 & 0x7F) | (0x80 if bool(val) else 0)
            elif name == 'settings.recordmode':
                b37 = (b37 & 0x9F) | ((int(val) & 0x03) << 5)
            elif name == 'settings.tianqi':
                b37 = (b37 & 0xF7) | (0x08 if bool(val) else 0)
            elif name == 'settings.langsel':
                b37 = (b37 & 0xFB) | ((int(val) & 1) << 2)
            else:
                b37 = (b37 & 0xFC) | (int(val) & 0x03)
            _wb(37, b37)
        elif name in ('settings.tailfreq', 'settings.noaa', 'settings.dispdir',
                      'settings.fminter', 'settings.noisecancel',
                      'settings.enhancefunc'):
            b38 = _b(38)
            if name == 'settings.tailfreq':
                b38 = (b38 & 0x1F) | ((int(val) & 0x07) << 5)
            elif name == 'settings.noaa':
                b38 = (b38 & 0xEF) | (0x10 if bool(val) else 0)
            elif name == 'settings.dispdir':
                b38 = (b38 & 0xF7) | (0x08 if bool(val) else 0)
            elif name == 'settings.fminter':
                b38 = (b38 & 0xFB) | (0x04 if bool(val) else 0)
            elif name == 'settings.noisecancel':
                b38 = (b38 & 0xFD) | (0x02 if bool(val) else 0)
            elif name == 'settings.enhancefunc':
                b38 = (b38 & 0xFE) | (1 if bool(val) else 0)
            _wb(38, b38)
        elif name == 'settings.skey1':
            _wb(48, int(val))
        elif name == 'settings.skey2':
            _wb(49, int(val))
        elif name == 'settings.lkey1':
            _wb(50, int(val))
        elif name == 'settings.lkey2':
            _wb(51, int(val))
        elif name == 'settings.skey3':
            _wb(52, int(val))
        elif name == 'settings.skey4':
            _wb(53, int(val))
        elif name == 'settings.lkey3':
            _wb(54, int(val))
        elif name == 'settings.lkey4':
            _wb(55, int(val))
        elif name == 'settings.powpassword':
            enc = str(val).encode(
                'ascii', errors='replace')[
                :8].ljust(
                8, b'\xFF')
            for i, b in enumerate(enc):
                _wb(64 + i, b)
        elif name == 'settings.wrpassword':
            enc = str(val).encode(
                'ascii', errors='replace')[
                :8].ljust(
                8, b'\xFF')
            for i, b in enumerate(enc):
                _wb(72 + i, b)
        elif name == 'settings.radioname':
            enc = _encode_name(str(val), 16)
            for i, b in enumerate(enc):
                _wb(80 + i, b)
        # ── VFO A / B ────────────────────────────────────────────────────────
        elif name.startswith('vfo_a.') or name.startswith('vfo_b.'):
            vfo_idx = 0 if name.startswith('vfo_a.') else 1
            base = ADDR_VFO + vfo_idx * _CHN_SIZE
            field = name.split('.', 1)[1]
            if field == 'rxfreq':
                _mwrite(self._mmap, base, _encode_freq_le(int(val)))
            elif field == 'txfreq':
                _mwrite(self._mmap, base + 4, _encode_freq_le(int(val)))
            elif field == 'txtone':
                m, v, p = self._str_to_tone(str(val))
                th, tl = _encode_tone(m, v, p)
                _mwb(self._mmap, base + 10, th)
                _mwb(self._mmap, base + 11, tl)
            elif field == 'rxtone':
                m, v, p = self._str_to_tone(str(val))
                th, tl = _encode_tone(m, v, p)
                _mwb(self._mmap, base + 8, th)
                _mwb(self._mmap, base + 9, tl)
            elif field == 'power':
                f16 = _mb(self._mmap, base + 16)
                _mwb(self._mmap, base + 16,
                     (f16 & 0x3F) | ((int(val) & 0x03) << 6))
            elif field == 'bandwidth':
                f16 = _mb(self._mmap, base + 16)
                _mwb(self._mmap, base + 16,
                     (f16 & 0xCF) | (0x10 if int(val) else 0))
            elif field == 'offsetdir':
                f16 = _mb(self._mmap, base + 16)
                _mwb(self._mmap, base + 16,
                     (f16 & 0xF3) | ((int(val) & 0x03) << 2))
            elif field == 'step':
                _mwb(self._mmap, base + 24, int(val))
            elif field == 'name':
                enc = _encode_name(str(val), 16)
                _mwrite(self._mmap, base + 32, enc)

        # ── Zones ────────────────────────────────────────────────────────────
        elif name == 'zones.count':
            _mwb(self._mmap, ADDR_ZONE_CNT, int(val))
        elif name.startswith('zones.zone') and '_name' in name:
            zi = int(name.split('zones.zone')[1].split('_')[0])
            enc = _encode_name(str(val), 16)
            _mwrite(self._mmap, ADDR_ZONES + zi * 152 + 136, enc)
        elif name.startswith('zones.zone') and '_preview' in name:
            pass  # read-only display field
        elif name.startswith('zones.zone') and '_chns' in name:
            zi = int(name.split('zones.zone')[1].split('_')[0])
            base = ADDR_ZONES + zi * 152
            ids = []
            for token in str(val).split(','):
                token = token.strip()
                if token.isdigit():
                    cid = int(token)
                    if 1 <= cid <= _MAX_CHN:
                        ids.append(cid)
            ids = ids[:67]
            _mwb(self._mmap, base, len(ids))
            _mwb(self._mmap, base + 1, 0)
            for j in range(67):
                cid = ids[j] if j < len(ids) else 0
                _mwb(self._mmap, base + 2 + j * 2, (cid >> 8) & 0xFF)
                _mwb(self._mmap, base + 3 + j * 2, cid & 0xFF)

        # ── Scan ─────────────────────────────────────────────────────────────
        elif name.startswith('scan.freq') and '_up' in name:
            si = int(name.split('scan.freq')[1].split('_')[0])
            _mwrite(
                self._mmap,
                ADDR_SCAN_FREQ + si * 8,
                _encode_freq_le(int(val)))
        elif name.startswith('scan.freq') and '_dw' in name:
            si = int(name.split('scan.freq')[1].split('_')[0])
            _mwrite(
                self._mmap,
                ADDR_SCAN_FREQ + si * 8 + 4,
                _encode_freq_le(int(val)))
        elif name == 'scan.scanmode':
            _mwb(self._mmap, ADDR_SCAN_PARA, int(val))
        elif name == 'scan.backscantim':
            _mwb(self._mmap, ADDR_SCAN_PARA + 1, int(val) + 5)
        elif name == 'scan.rxresume':
            _mwb(self._mmap, ADDR_SCAN_PARA + 2, int(val) + 1)
        elif name == 'scan.txresume':
            _mwb(self._mmap, ADDR_SCAN_PARA + 3, int(val) + 1)
        elif name == 'scan.rtnchtype':
            _mwb(self._mmap, ADDR_SCAN_PARA + 4, int(val))
        elif name == 'scan.prioscan':
            _mwb(self._mmap, ADDR_SCAN_PARA + 5, 1 if bool(val) else 0)
        elif name == 'scan.priochannel':
            v = int(val)
            _mwb(self._mmap, ADDR_SCAN_PARA + 6, (v >> 8) & 0xFF)
            _mwb(self._mmap, ADDR_SCAN_PARA + 7, v & 0xFF)
        elif name == 'scan.scanrange':
            _mwb(self._mmap, ADDR_SCAN_PARA + 8, int(val))

        # ── DTMF ─────────────────────────────────────────────────────────────
        elif name == 'dtmf.dtmfsw':
            _mwb(self._mmap, ADDR_DTMF, 1 if bool(val) else 0)
        elif name == 'dtmf.codespeed':
            _mwb(self._mmap, ADDR_DTMF + 1, int(val))
        elif name == 'dtmf.firstcodetim':
            _mwb(self._mmap, ADDR_DTMF + 2, int(val) // 10)
        elif name == 'dtmf.pretime':
            _mwb(self._mmap, ADDR_DTMF + 3, int(val) // 10)
        elif name == 'dtmf.codedly':
            _mwb(self._mmap, ADDR_DTMF + 4, int(val) // 10)
        elif name == 'dtmf.pttidpause':
            _mwb(self._mmap, ADDR_DTMF + 5, int(val))
        elif name == 'dtmf.dtmftone':
            _mwb(self._mmap, ADDR_DTMF + 6, 1 if bool(val) else 0)
        elif name == 'dtmf.resettime':
            _mwb(self._mmap, ADDR_DTMF + 7, int(val) + 10)
        elif name == 'dtmf.sepcode':
            _mwb(self._mmap, ADDR_DTMF + 8, int(val) + 10)
        elif name == 'dtmf.grpcode':
            v = int(val)
            _mwb(self._mmap, ADDR_DTMF + 9, v + 9 if v > 0 else 0xFF)
        elif name == 'dtmf.decrsp':
            _mwb(self._mmap, ADDR_DTMF + 10, int(val))
        elif name == 'dtmf.did':
            _mwrite(
                self._mmap,
                ADDR_DTMF + 16,
                _encode_dtmf_bytes(
                    str(val),
                    3))
        elif name == 'dtmf.bot':
            _mwrite(self._mmap, ADDR_DTMF + 24, _encode_dtmf_bytes(str(val)))
        elif name == 'dtmf.eot':
            _mwrite(self._mmap, ADDR_DTMF + 40, _encode_dtmf_bytes(str(val)))
        elif name == 'dtmf.stun':
            _mwrite(self._mmap, ADDR_DTMF + 56, _encode_dtmf_bytes(str(val)))
        elif name == 'dtmf.kill':
            _mwrite(self._mmap, ADDR_DTMF + 72, _encode_dtmf_bytes(str(val)))
        elif name.startswith('dtmf_enc.') or name.startswith('dtmf_enc_en.'):
            parts = name.split('.')
            di = int(parts[1])
            if name.startswith('dtmf_enc_en.'):
                # Update enable bit
                flags_raw = _mread(self._mmap, ADDR_DTMF_FLAGS, 2)
                use_flg = ~((flags_raw[1] << 8) | flags_raw[0]) & 0xFFFF
                if bool(val):
                    use_flg |= (1 << di)
                else:
                    use_flg &= ~(1 << di)
                raw16 = ~use_flg & 0xFFFF
                _mwb(self._mmap, ADDR_DTMF_FLAGS, raw16 & 0xFF)
                _mwb(self._mmap, ADDR_DTMF_FLAGS + 1, (raw16 >> 8) & 0xFF)
            else:
                _mwrite(self._mmap, ADDR_DTMF_ENC + di * 16,
                        _encode_dtmf_bytes(str(val)))

        # ── 2-Tone ───────────────────────────────────────────────────────────
        elif name == 'twotone.firsttone':
            _mwb(self._mmap, ADDR_2TONE, (int(val) + 1) * 5)
        elif name == 'twotone.secondtone':
            _mwb(self._mmap, ADDR_2TONE + 1, (int(val) + 1) * 5)
        elif name == 'twotone.tonedur':
            _mwb(self._mmap, ADDR_2TONE + 2, (int(val) + 1) * 5)
        elif name == 'twotone.toneint':
            _mwb(self._mmap, ADDR_2TONE + 3, int(val))
        elif name == 'twotone.stonesw':
            _mwb(self._mmap, ADDR_2TONE + 4, 1 if bool(val) else 0)
        elif name.startswith('twotone_enc.'):
            parts = name.split('.')
            ti = int(parts[1].split('_')[0])
            field = parts[1].split('_', 1)[1]
            base = ADDR_2TONE_ENC + ti * 16
            if field == 'f1':
                v = int(val)
                _mwb(self._mmap, base, (v >> 8) & 0xFF)
                _mwb(self._mmap, base + 1, v & 0xFF)
            elif field == 'f2':
                v = int(val)
                _mwb(self._mmap, base + 2, (v >> 8) & 0xFF)
                _mwb(self._mmap, base + 3, v & 0xFF)
            elif field == 'name':
                enc = str(val).encode('ascii', errors='replace')[:12]
                enc = enc.ljust(12, b'\x00')
                _mwrite(self._mmap, base + 4, enc)
        elif name == 'twotone.decodersp':
            _mwb(self._mmap, ADDR_2TONE_DEC, int(val))
        elif name == 'twotone.resetim':
            _mwb(self._mmap, ADDR_2TONE_DEC + 1, int(val) + 10)
        elif name == 'twotone.decformat':
            _mwb(self._mmap, ADDR_2TONE_DEC + 2, int(val))
        elif name in ('twotone.atone', 'twotone.btone',
                      'twotone.ctone', 'twotone.dtone'):
            tidx = ['twotone.atone', 'twotone.btone',
                    'twotone.ctone', 'twotone.dtone'].index(name)
            v = int(val)
            _mwb(self._mmap, ADDR_2TONE_DEC + 4 + tidx * 2, (v >> 8) & 0xFF)
            _mwb(self._mmap, ADDR_2TONE_DEC + 5 + tidx * 2, v & 0xFF)

        # ── 5-Tone ───────────────────────────────────────────────────────────
        elif name.startswith('fivetone_enc.'):
            parts = name.split('.')
            fi = int(parts[1].split('_')[0])
            field = parts[1].split('_', 1)[1]
            base = ADDR_5TONE_ENC + fi * 32
            if field == 'stand':
                _mwb(self._mmap, base, int(val))
            elif field == 'codetime':
                _mwb(self._mmap, base + 1, int(val) + 7)
            elif field == 'codelen':
                _mwb(self._mmap, base + 2, int(val))
            elif field == 'id':
                _mwrite(self._mmap, base + 3, _encode_5tone_id(str(val)))
            elif field == 'scall':
                _mwb(self._mmap, base + 23, int(val))
            elif field == 'name':
                enc = str(val).encode('ascii', errors='replace')[:8]
                enc = enc.ljust(8, b'\x00')
                _mwrite(self._mmap, base + 24, enc)
            elif field == 'en':
                en_byte = fi // 8
                en_bit = fi % 8
                addr = ADDR_5TONE_TBL + en_byte
                bv = _mb(self._mmap, addr)
                if bool(val):
                    bv &= ~(1 << en_bit)
                else:
                    bv |= (1 << en_bit)
                _mwb(self._mmap, addr, bv)
        elif name == 'fivetone.decrsp':
            _mwb(self._mmap, ADDR_5TONE_DEC, int(val))
        elif name == 'fivetone.decstand':
            _mwb(self._mmap, ADDR_5TONE_DEC + 1, int(val))
        elif name == 'fivetone.dectim':
            _mwb(self._mmap, ADDR_5TONE_DEC + 2, int(val) + 7)
        elif name == 'fivetone.pretime':
            _mwb(self._mmap, ADDR_5TONE_DEC + 11, int(val) // 10)
        elif name == 'fivetone.codedly':
            _mwb(self._mmap, ADDR_5TONE_DEC + 12, int(val) // 10)
        elif name == 'fivetone.resettime':
            _mwb(self._mmap, ADDR_5TONE_DEC + 14, int(val) + 10)
        elif name == 'fivetone.fiveani':
            _mwb(self._mmap, ADDR_5TONE_DEC + 16, 1 if bool(val) else 0)

        # ── MDC-1200 ─────────────────────────────────────────────────────────
        elif name.startswith('mdc_para.'):
            parts = name.split('.')
            mi = int(parts[1].split('_')[0])
            field = parts[1].split('_', 1)[1]
            base = ADDR_MDC_PARA + mi * 8
            if field == 'ctrl':
                b0 = _mb(self._mmap, base)
                _mwb(
                    self._mmap, base, (b0 & 0x7F) | (
                        0x80 if bool(val) else 0))
            elif field == 'dectone':
                b0 = _mb(self._mmap, base)
                _mwb(
                    self._mmap, base, (b0 & 0xBF) | (
                        0x40 if bool(val) else 0))
            elif field == 'encid':
                v = int(val)
                _mwb(self._mmap, base + 1, (v >> 8) & 0xFF)
                _mwb(self._mmap, base + 2, v & 0xFF)
        elif name == 'mdc.selfid':
            v = int(val)
            _mwb(self._mmap, ADDR_MDC_BIIS, (v >> 8) & 0xFF)
            _mwb(self._mmap, ADDR_MDC_BIIS + 1, v & 0xFF)
        elif name == 'mdc.grpid':
            v = int(val)
            _mwb(self._mmap, ADDR_MDC_BIIS + 2, (v >> 8) & 0xFF)
            _mwb(self._mmap, ADDR_MDC_BIIS + 3, v & 0xFF)
        elif name == 'mdc.tonesw':
            _mwb(self._mmap, ADDR_MDC_BIIS + 8, 1 if bool(val) else 0)
        elif name.startswith('mdc_dec.'):
            parts = name.split('.')
            mi = int(parts[1].split('_')[0])
            field = parts[1].split('_', 1)[1]
            base = ADDR_MDC_DEC + mi * 16
            if field == 'id':
                try:
                    v = int(str(val))
                except ValueError:
                    v = 0
                _mwb(self._mmap, base, (v >> 8) & 0xFF)
                _mwb(self._mmap, base + 1, v & 0xFF)
            elif field == 'name':
                enc = _encode_name(str(val), 12)
                _mwrite(self._mmap, base + 4, enc)
            elif field == 'en':
                en_byte = mi // 8
                en_bit = mi % 8
                addr = ADDR_MDC_TBL + en_byte
                bv = _mb(self._mmap, addr)
                if bool(val):
                    bv &= ~(1 << en_bit)
                else:
                    bv |= (1 << en_bit)
                _mwb(self._mmap, addr, bv)

        # ── Emergency ────────────────────────────────────────────────────────
        elif name.startswith('emerg.'):
            parts = name.split('.')
            ei = int(parts[1].split('_')[0])
            field = parts[1].split('_', 1)[1]
            base = ADDR_EMERG + ei * 16
            _field_map = {
                'dur': 0, 'chsel': 1, 'rxtime': 2, 'txtime': 3,
                'exgtime': 4, 'grpno': 5,
                'mode': 6, 'type': 7, 'chn': 14, 'zone': 15,
            }
            if field in _field_map:
                _mwb(self._mmap, base + _field_map[field], int(val))

        # ── APRS ─────────────────────────────────────────────────────────────
        elif name.startswith('aprs.'):
            field = name.split('.', 1)[1]
            base = ADDR_APRS
            if field == 'desno':
                enc = str(val).encode('ascii', errors='replace')[:6]
                enc = enc.ljust(6, b'\x20')
                _mwrite(self._mmap, base, enc)
            elif field == 'desid':
                _mwb(self._mmap, base + 6, int(val))
            elif field == 'srcno':
                enc = str(val).encode('ascii', errors='replace')[:6]
                enc = enc.ljust(6, b'\x20')
                _mwrite(self._mmap, base + 8, enc)
            elif field == 'srcid':
                _mwb(self._mmap, base + 14, int(val))
            elif field in ('passall', 'position', 'mice', 'object', 'item',
                           'message', 'wxreport', 'nmeareport'):
                b7 = _mb(self._mmap, base + 7)
                bit_map = {
                    'passall': 7, 'position': 6, 'mice': 5, 'object': 4,
                    'item': 3, 'message': 2, 'wxreport': 1, 'nmeareport': 0,
                }
                bit = bit_map[field]
                b7 = (b7 & ~(1 << bit)) | ((1 if bool(val) else 0) << bit)
                _mwb(self._mmap, base + 7, b7)
            elif field in ('statusreport', 'other', 'power', 'band',
                           'beeptone', 'longdir', 'latdir'):
                b15 = _mb(self._mmap, base + 15)
                if field == 'statusreport':
                    b15 = (b15 & 0x7F) | (0x80 if bool(val) else 0)
                elif field == 'other':
                    b15 = (b15 & 0xBF) | (0x40 if bool(val) else 0)
                elif field == 'power':
                    b15 = (b15 & 0xCF) | ((int(val) & 0x03) << 4)
                elif field == 'band':
                    b15 = (b15 & 0xF7) | (0x08 if bool(val) else 0)
                elif field == 'beeptone':
                    b15 = (b15 & 0xFB) | (0x04 if bool(val) else 0)
                elif field == 'longdir':
                    b15 = (b15 & 0xFD) | (0x02 if bool(val) else 0)
                elif field == 'latdir':
                    b15 = (b15 & 0xFE) | (1 if bool(val) else 0)
                _mwb(self._mmap, base + 15, b15)
            elif field == 'pretime':
                _mwb(self._mmap, base + 16, int(val))
            elif field == 'codedly':
                _mwb(self._mmap, base + 17, int(val))
            elif field == 'ctdcs':
                m, v, p = self._str_to_tone(str(val))
                th, tl = _encode_tone(m, v, p)
                _mwb(self._mmap, base + 18, th)
                _mwb(self._mmap, base + 19, tl)
            elif field in ('beacon', 'heighttype', 'pttid',
                           'encodetype', 'micetype'):
                b92 = _mb(self._mmap, base + 92)
                if field == 'beacon':
                    b92 = (b92 & 0x7F) | (0x80 if bool(val) else 0)
                elif field == 'heighttype':
                    b92 = (b92 & 0xBF) | (0x40 if bool(val) else 0)
                elif field == 'pttid':
                    b92 = (b92 & 0xCF) | ((int(val) & 0x03) << 4)
                elif field == 'encodetype':
                    b92 = (b92 & 0xF7) | (0x08 if bool(val) else 0)
                elif field == 'micetype':
                    b92 = (b92 & 0xF8) | (int(val) & 0x07)
                _mwb(self._mmap, base + 92, b92)
            elif field == 'sendinterval':
                _mwb(self._mmap, base + 88, int(val))
            elif field == 'regularlysend':
                _mwb(self._mmap, base + 89, 1 if bool(val) else 0)
            elif field == 'aprsdistime':
                _mwb(self._mmap, base + 90, int(val))
            elif field == 'txtlength':
                _mwb(self._mmap, base + 95, int(val))
            elif field == 'txt':
                enc = str(val).encode('utf-8', errors='replace')[:60]
                enc = enc.ljust(60, b'\x00')
                _mwrite(self._mmap, base + 108, enc)
                _mwb(self._mmap, base + 95, len(str(val).encode('utf-8')[:60]))
            elif field == 'postable':
                c = str(val)[0] if str(val) else '/'
                _mwb(self._mmap, base + 20, ord(c) & 0xFF)
            elif field == 'posicon':
                c = str(val)[0] if str(val) else ' '
                _mwb(self._mmap, base + 21, ord(c) & 0xFF)
            elif field == 'lon':
                v = int(val)
                _mwrite(self._mmap, base + 96, struct.pack('<i', v))
            elif field == 'lat':
                v = int(val)
                _mwrite(self._mmap, base + 100, struct.pack('<i', v))
            elif field == 'height':
                v = int(val)
                _mwrite(self._mmap, base + 104, struct.pack('<i', v))
            elif field.startswith('txcs') and not field.startswith('txcsid'):
                ai = int(field[4:])
                enc = str(val).encode('ascii', errors='replace')[:6]
                enc = enc.ljust(6, b'\x20')
                _mwrite(self._mmap, base + 24 + ai * 8, enc)
            elif field.startswith('txcsid'):
                ai = int(field[6:])
                _mwb(self._mmap, base + 24 + ai * 8 + 6, int(val))
            elif field.startswith('txfreq'):
                ai = int(field[6:])
                try:
                    freq_hz = int(round(float(str(val).strip()) * 1_000_000))
                except ValueError:
                    freq_hz = 0
                _mwrite(self._mmap, base + 168 + ai * 4,
                        _encode_freq_le(freq_hz))
            elif field == 'rxcscount':
                _mwb(self._mmap, base + 22, int(val))
            elif field.startswith('rxcsfilt'):
                ai = int(field[8:])
                _mwb(self._mmap, base + 200 + ai * 8 + 7,
                     1 if bool(val) else 0)
            elif field.startswith('rxcsid'):
                ai = int(field[6:])
                _mwb(self._mmap, base + 200 + ai * 8 + 6, int(val))
            elif field.startswith('rxcs'):
                ai = int(field[4:])
                enc = str(val).encode('ascii', errors='replace')[:6]
                enc = enc.ljust(6, b'\x20')
                _mwrite(self._mmap, base + 200 + ai * 8, enc)

        # ── GPS Book ─────────────────────────────────────────────────────────
        elif name.startswith('gps_book.'):
            parts = name.split('.')
            gi = int(parts[1].split('_')[0])
            field = parts[1].split('_', 1)[1]
            base = ADDR_GPS_BOOK + gi * 16
            if field == 'en':
                en_byte = gi // 8
                en_bit = gi % 8
                addr = ADDR_GPS_FLAGS + en_byte
                bv = _mb(self._mmap, addr)
                if bool(val):
                    bv &= ~(1 << en_bit)
                else:
                    bv |= (1 << en_bit)
                _mwb(self._mmap, addr, bv)
            elif field == 'code':
                _mwb(self._mmap, base, int(val))
            elif field == 'name':
                enc = _encode_name(str(val), 14)
                _mwrite(self._mmap, base + 2, enc)

        else:
            LOG.debug('5RH: unhandled setting %s', name)
