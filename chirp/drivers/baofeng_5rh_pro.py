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
total memory. All wire bytes are XOR'd with a per-session random seed (1-254).
Memory is XOR-decrypted in bulk after a full download.
"""

import logging
import random
import struct
import time

from chirp import chirp_common, directory, errors, memmap
from chirp.settings import (RadioSetting, RadioSettingGroup, RadioSettings,
                             RadioSettingValueBoolean, RadioSettingValueInteger,
                             RadioSettingValueList, RadioSettingValueString)

LOG = logging.getLogger(__name__)

# ── Protocol constants ────────────────────────────────────────────────────────

BAUD_PRIMARY = 19200
BAUD_FALLBACK = 115200

# 16-byte wake pulse sent before handshake (12×0x00 + 4×0xFF)
_T_INFO = b'\x00' * 12 + b'\xFF' * 4

_MAGIC_PROGRAM = b'PROGRAM'       # 7 bytes; byte 7 = seed (sent in plaintext)
_MAGIC_INFO    = b'INFORMATION'   # 11 bytes
_MAGIC_END     = b'END\x00'       # 4 bytes
_ACK           = 0x41             # 'A' — all ACKs are this value XOR seed

_BLOCK_SIZE = 4096
_MEM_SIZE   = 49152               # 0xC000 = 12 × 4096

# ── Memory map offsets ────────────────────────────────────────────────────────

ADDR_DEVICE     = 0x0000   # 128 bytes
ADDR_CHANNELS   = 0x0080   # 640 × 48 = 30720 bytes
ADDR_VFO        = 0x7900   # 2 × 48 = 96 bytes
ADDR_SETTINGS   = 0x7980   # 128 bytes
ADDR_CHN_FLAGS  = 0x7A20   # 80 bytes  (640 / 8)
ADDR_ZONE_CNT   = 0x7A80   # 1 byte
ADDR_ZONES      = 0x7A90   # 10 × 152 = 1520 bytes
ADDR_SCAN_FREQ  = 0x8100   # 16 × 8 = 128 bytes
ADDR_SCAN_PARA  = 0x8180
ADDR_SCAN_FLAGS = 0x81A0   # 80 bytes
ADDR_DTMF       = 0x8200
ADDR_2TONE      = 0x8400
ADDR_5TONE_ENC  = 0x8680
ADDR_MDC        = 0x9580
ADDR_EMERG      = 0x9D00
ADDR_APRS       = 0x9E00   # 456 bytes
ADDR_GPS_FLAGS  = 0xA000   # 10 bytes  (80 / 8)
ADDR_GPS_BOOK   = 0xA010   # 80 × 16 = 1280 bytes

# ── Channel struct dimensions ─────────────────────────────────────────────────

_CHN_SIZE = 48
_MAX_CHN  = 640

# ── Setting value lists ───────────────────────────────────────────────────────

LIST_WORKMODE  = ['Frequency', 'Channel']
LIST_BANDWIDTH = ['Wide', 'Narrow']
LIST_POWER     = ['High', 'Mid', 'Low']
LIST_VOICE     = ['Off', 'English', 'Chinese']
LIST_SQUELCH   = [str(x) for x in range(0, 10)]
LIST_APO       = ['Off'] + ['%d min' % x for x in range(1, 61)]
LIST_TOT       = ['Off'] + ['%d s' % x for x in range(15, 615, 15)]
LIST_BACKLIGHT = ['Off', '5 s', '10 s', '20 s', '30 s', 'Always On']
LIST_BLIGHT_LV = [str(x) for x in range(1, 6)]
LIST_GPS_MODE  = ['GPS', 'Beidou', 'GPS+Beidou']
LIST_TZ        = [str(x) for x in range(-12, 13)]
LIST_DISP_MODE = ['Frequency', 'Channel Number', 'Name']
LIST_SCAN_MODE = ['Time', 'Carrier', 'Search']
LIST_PTTID     = ['Off', 'BOT', 'EOT', 'Both']
LIST_DUPLEX    = ['Off', '+', '-']
LIST_OFFSETDIR = ['Off', '+', '-', 'Simplex']
LIST_SQTYPE    = ['Off', 'CTCSS', 'DCS', 'CTCSS/DCS']
LIST_SIGNAL    = ['Off', 'DTMF', '2-Tone', '5-Tone', 'MDC-1200']
LIST_BCL       = ['Off', 'Carrier', 'Tone']
LIST_BT_PAIR   = ['Off', 'Always', 'PTT']

_CHARSET = chirp_common.CHARSET_ASCII
for _x in range(0xB0, 0xD7):
    for _y in range(0xA1, 0xFF):
        try:
            _CHARSET += bytes([_x, _y]).decode('gb2312')
        except Exception:
            pass

# ── Tone helpers ──────────────────────────────────────────────────────────────

def _decode_tone(datH, datL):
    """Decode 2-byte BCD tone to (mode, tone, polarity).

    Returns ('', 0, 'N') for off.  Mode is 'Tone' or 'DTCS'.
    CTCSS: bit7 of datH == 0, value is BCD (digits treated as decimal).
    DCS:   bit7 of datH == 1, bits[10:0] = code; bit6 == 1 → inverted.
    """
    if datH == 0x00:
        return '', 0, 'N'
    if datH == 0xFF:
        return '', 0, 'N'
    if datH & 0x80:
        # DCS
        pol = 'R' if (datH & 0xC0) == 0xC0 else 'N'
        code_val = ((datH & 0x07) << 8) | datL
        # stored value uses hex digits as decimal digits
        code = int('%x' % code_val)
        return 'DTCS', code, pol
    else:
        # CTCSS — BCD: treat the 16-bit value's hex representation as decimal
        raw = (datH << 8) | datL
        bcd_decimal = int('%x' % raw)            # e.g. 0x0885 → 885
        tone_hz = bcd_decimal / 10.0             # e.g. 885 → 88.5
        return 'Tone', tone_hz, 'N'


def _encode_tone(mode, tone, pol):
    """Encode (mode, tone, polarity) to (datH, datL) bytes."""
    if mode == '' or mode is None:
        return 0x00, 0x00
    if mode == 'Tone':
        bcd_decimal = int(round(tone * 10))      # e.g. 88.5 → 885
        raw = int('%d' % bcd_decimal, 16)        # interpret decimal digits as hex
        return (raw >> 8) & 0x7F, raw & 0xFF
    if mode in ('DTCS', 'TSQL'):
        # TSQL uses CTCSS in CHIRP's split_tone; DCS matches 'DTCS'
        if mode == 'TSQL':
            bcd_decimal = int(round(tone * 10))
            raw = int('%d' % bcd_decimal, 16)
            return (raw >> 8) & 0x7F, raw & 0xFF
        code_val = int('%d' % int(tone), 16)     # CHIRP code 23 → 0x23 = 35
        h = 0x80 | ((code_val >> 8) & 0x07)
        if pol == 'R':
            h |= 0x40
        return h, code_val & 0xFF
    return 0x00, 0x00


# ── Frequency helpers ─────────────────────────────────────────────────────────

def _decode_freq(data4):
    """Decode 4-byte lbcd-LE frequency → Hz."""
    le_int = struct.unpack_from('<I', data4)[0]
    # le_int is the BCD value whose hex string is the frequency digits
    bcd_str = '%08X' % le_int               # e.g. 0x14625000 → "14625000"
    bcd_dec = int(bcd_str)                  # treat hex digits as decimal
    return bcd_dec * 10                     # units → Hz (100 Hz → Hz)


def _encode_freq(hz):
    """Encode Hz frequency → 4-byte lbcd-LE."""
    units = hz // 10                        # 146_250_000 Hz → 14_625_000
    bcd_str = '%08d' % units               # "14625000"
    le_int = int(bcd_str, 16)              # interpret as hex → 0x14625000
    return struct.pack('<I', le_int)


# ── GB2312 byte-swapped string helpers ───────────────────────────────────────

def _decode_name(raw16):
    """Decode 16-byte GB2312 name (byte-swapped pairs, 0xFF terminated)."""
    result = bytearray()
    for i in range(0, 16, 2):
        if raw16[i] == 0xFF or raw16[i] == 0x00:
            break
        result += bytes([raw16[i], raw16[i + 1]])
    try:
        return result.decode('gb2312').strip()
    except UnicodeDecodeError:
        return result.decode('latin-1', errors='replace').strip()


def _encode_name(text, maxbytes=16):
    """Encode name string to padded GB2312 bytes (0xFF padded)."""
    try:
        encoded = text.encode('gb2312')[:maxbytes]
    except (UnicodeEncodeError, LookupError):
        encoded = text.encode('ascii', errors='replace')[:maxbytes]
    # Pad to maxbytes with 0xFF
    return encoded.ljust(maxbytes, b'\xFF')


# ── Serial I/O helpers ────────────────────────────────────────────────────────

def _xwrite(pipe, data, seed):
    """XOR-encrypt data with seed and write to port."""
    enc = bytes(b ^ seed for b in data)
    pipe.write(enc)


def _xread(pipe, n, timeout=2.0):
    """Read n bytes with a deadline; raise RadioError on timeout."""
    buf = b''
    deadline = time.time() + timeout
    while len(buf) < n and time.time() < deadline:
        chunk = pipe.read(n - len(buf))
        if chunk:
            buf += chunk
    if len(buf) < n:
        raise errors.RadioError(
            'Timeout reading from radio (got %d of %d bytes)' % (len(buf), n))
    return buf


def _wait_ack(pipe, seed, label, timeout=2.0):
    """Read 1 byte, decode XOR, assert == 0x41; raise on failure."""
    b = _xread(pipe, 1, timeout)
    decoded = b[0] ^ seed
    if decoded != _ACK:
        raise errors.RadioError(
            '%s: expected ACK 0x41, got 0x%02x (raw 0x%02x)' %
            (label, decoded, b[0]))


# ── Handshake ─────────────────────────────────────────────────────────────────

def _do_handshake(pipe, seed, direction='R'):
    """Execute the 6-state 5RH PRO handshake.

    direction: 'R' for read, 'W' for write.
    Tries 19200 baud first; falls back to 115200 if no ACK in state 2.
    Returns the 16-byte device-model response (decoded).
    """
    # ── State 1: wake pulse ───────────────────────────────────────────────────
    pipe.write(_T_INFO)

    # ── State 2: wait for unencrypted ACK from radio ──────────────────────────
    pipe.timeout = 0.3
    ack_byte = pipe.read(1)
    if not ack_byte or ack_byte[0] != 0x41:
        # Try fallback baud
        LOG.debug('5RH: no ACK at 19200, trying 115200')
        pipe.baudrate = BAUD_FALLBACK
        pipe.write(_T_INFO)
        pipe.timeout = 0.5
        ack_byte = pipe.read(1)
        if not ack_byte or ack_byte[0] != 0x41:
            raise errors.RadioNoResponse()
    pipe.timeout = 2.0

    # ── Send PROGRAM header (bytes 0-6 XOR'd, byte 7 = seed plaintext) ───────
    hdr = bytearray(8)
    for i, c in enumerate(_MAGIC_PROGRAM):
        hdr[i] = seed ^ c
    hdr[7] = seed
    pipe.write(bytes(hdr))

    # ── State 3: XOR-encoded ACK from radio ───────────────────────────────────
    _wait_ack(pipe, seed, 'PROGRAM ACK')

    # ── Send password (8 bytes, default all 0xFF, XOR'd) ─────────────────────
    pwd = b'\xFF' * 8
    _xwrite(pipe, pwd, seed)

    # ── State 4: ACK ──────────────────────────────────────────────────────────
    _wait_ack(pipe, seed, 'Password ACK')

    # ── Send INFORMATION header (11 bytes, XOR'd) ─────────────────────────────
    _xwrite(pipe, _MAGIC_INFO, seed)

    # ── State 5: 16-byte device model response ────────────────────────────────
    raw16 = _xread(pipe, 16)
    model_bytes = bytes(b ^ seed for b in raw16)
    # Null/0xFF terminated model string
    model_str = model_bytes.split(b'\x00')[0].split(b'\xff')[0].decode(
        'ascii', errors='replace')
    LOG.info('5RH PRO model response: %r', model_str)

    # ── Send direction byte (R or W, XOR'd) ───────────────────────────────────
    dir_byte = ord(direction)
    pipe.write(bytes([seed ^ dir_byte]))

    # ── State 6: final ACK ────────────────────────────────────────────────────
    _wait_ack(pipe, seed, 'Direction ACK')

    return model_bytes


# ── Download / Upload ─────────────────────────────────────────────────────────

def _download_5rh(radio):
    """Download 49152 bytes from radio, XOR-decrypt, return bytes."""
    pipe = radio.pipe
    pipe.baudrate = BAUD_PRIMARY
    pipe.timeout = 2.0

    seed = random.randint(1, 254)
    LOG.debug('5RH download seed: 0x%02x', seed)

    _do_handshake(pipe, seed, 'R')

    # ── Read 12 blocks × 4096 bytes ──────────────────────────────────────────
    buf = bytearray(_MEM_SIZE)
    rx_cnt = 0

    status = chirp_common.Status()
    status.max = _MEM_SIZE // _BLOCK_SIZE
    status.msg = 'Cloning from radio...'

    while rx_cnt < _MEM_SIZE:
        # 4-byte read request: [0x52, addrH, addrL, 0x00] all XOR'd
        req = bytes([0x52, (rx_cnt >> 8) & 0xFF, rx_cnt & 0xFF, 0x00])
        _xwrite(pipe, req, seed)

        # Radio responds with 4-byte header + 4096-byte block (raw, XOR'd)
        pipe.timeout = 5.0
        response = _xread(pipe, _BLOCK_SIZE + 4, timeout=5.0)
        # Skip 4-byte header; copy raw data
        buf[rx_cnt:rx_cnt + _BLOCK_SIZE] = response[4:]
        rx_cnt += _BLOCK_SIZE

        status.cur = rx_cnt // _BLOCK_SIZE
        radio.status_fn(status)

    # ── Send END, wait ACK ────────────────────────────────────────────────────
    _xwrite(pipe, _MAGIC_END, seed)
    _wait_ack(pipe, seed, 'END ACK', timeout=3.0)

    # ── XOR-decrypt entire buffer ─────────────────────────────────────────────
    for i in range(_MEM_SIZE):
        buf[i] ^= seed

    return bytes(buf)


def _upload_5rh(radio):
    """XOR-encrypt and upload radio memory."""
    pipe = radio.pipe
    pipe.baudrate = BAUD_PRIMARY
    pipe.timeout = 2.0

    seed = random.randint(1, 254)
    LOG.debug('5RH upload seed: 0x%02x', seed)

    _do_handshake(pipe, seed, 'W')

    data = radio.get_mmap()

    status = chirp_common.Status()
    status.max = _MEM_SIZE // _BLOCK_SIZE
    status.msg = 'Cloning to radio...'

    tx_cnt = 0
    while tx_cnt < _MEM_SIZE:
        block = bytes(data[tx_cnt:tx_cnt + _BLOCK_SIZE])
        hdr = bytes([0x57, (tx_cnt >> 8) & 0xFF, tx_cnt & 0xFF, 0x00])
        frame = bytearray(hdr + block)
        # XOR entire frame
        enc = bytes(b ^ seed for b in frame)
        pipe.write(enc)
        pipe.timeout = 5.0
        _wait_ack(pipe, seed, 'Write block 0x%04x ACK' % tx_cnt, timeout=5.0)
        tx_cnt += _BLOCK_SIZE

        status.cur = tx_cnt // _BLOCK_SIZE
        radio.status_fn(status)

    _xwrite(pipe, _MAGIC_END, seed)
    _wait_ack(pipe, seed, 'Upload END ACK', timeout=3.0)


# ── Channel parsing ───────────────────────────────────────────────────────────

def _mb(mmap, addr):
    """Read a single byte from mmap as int."""
    return ord(mmap[addr])


def _mwb(mmap, addr, val):
    """Write a single byte to mmap."""
    mmap[addr] = bytes([val & 0xFF])


def _mwrite(mmap, addr, data):
    """Write multiple bytes to mmap one byte at a time."""
    for i, b in enumerate(data):
        mmap[addr + i] = bytes([b])


def _chn_used(mmap, idx):
    """Return True if channel idx is marked valid in the flag bitmap."""
    flag_byte = idx // 8
    flag_bit  = idx % 8
    byte_val  = _mb(mmap, ADDR_CHN_FLAGS + flag_byte)
    # bit = 0 means channel is USED (inverted in CPS ConvertChnValidFlg)
    return ((byte_val >> flag_bit) & 1) == 0


def _set_chn_used(mmap, idx, used):
    flag_byte = idx // 8
    flag_bit  = idx % 8
    b = _mb(mmap, ADDR_CHN_FLAGS + flag_byte)
    if used:
        b &= ~(1 << flag_bit)
    else:
        b |= (1 << flag_bit)
    _mwb(mmap, ADDR_CHN_FLAGS + flag_byte, b)


def _read_chn_raw(mmap, idx):
    """Return 48-byte bytearray for channel idx."""
    off = ADDR_CHANNELS + idx * _CHN_SIZE
    return bytearray(mmap[off:off + _CHN_SIZE])


def _write_chn_raw(mmap, idx, raw48):
    off = ADDR_CHANNELS + idx * _CHN_SIZE
    _mwrite(mmap, off, raw48)


# ── Radio class ───────────────────────────────────────────────────────────────

@directory.register
class BaofengUV5RMPlusGPS(chirp_common.CloneModeRadio):
    """Baofeng UV-5RM Plus (GPS) — 5RH PRO protocol."""

    VENDOR  = 'Baofeng'
    MODEL   = 'UV-5RM Plus (GPS)'
    BAUD_RATE = BAUD_PRIMARY

    CHANNELS = _MAX_CHN
    MEM_SIZE = _MEM_SIZE

    POWER_LEVELS = [
        chirp_common.PowerLevel('High', watts=5),
        chirp_common.PowerLevel('Mid',  watts=2),
        chirp_common.PowerLevel('Low',  watts=0.5),
    ]

    MODES = ['FM', 'NFM', 'AM']

    VALID_BANDS = [
        (108_000_000, 136_000_000),    # airband RX
        (136_000_000, 174_000_000),    # VHF
        (400_000_000, 480_000_000),    # UHF
        (200_000_000, 260_000_000),    # 220 MHz
    ]

    DTCS_CODES = sorted(chirp_common.DTCS_CODES)
    STEPS = [2.5, 5.0, 6.25, 10.0, 12.5, 20.0, 25.0, 50.0]
    VALID_CHARS = _CHARSET
    LENGTH_NAME = 8

    @classmethod
    def get_prompts(cls):
        rp = chirp_common.RadioPrompts()
        rp.pre_download = _(
            'Follow these steps to download:\n'
            '1. Turn off radio\n'
            '2. Connect programming cable\n'
            '3. Turn on radio\n'
            '4. Click OK to begin download\n')
        rp.pre_upload = _(
            'Follow these steps to upload:\n'
            '1. Turn off radio\n'
            '2. Connect programming cable\n'
            '3. Turn on radio\n'
            '4. Click OK to begin upload\n')
        return rp

    def get_features(self):
        rf = chirp_common.RadioFeatures()
        rf.has_settings     = True
        rf.has_bank         = False
        rf.has_tuning_step  = False
        rf.can_odd_split    = True
        rf.has_name         = True
        rf.has_offset       = True
        rf.has_mode         = True
        rf.has_dtcs         = True
        rf.has_rx_dtcs      = True
        rf.has_dtcs_polarity = True
        rf.has_ctone        = True
        rf.has_cross        = True
        rf.valid_modes      = self.MODES
        rf.valid_characters = self.VALID_CHARS
        rf.valid_name_length = self.LENGTH_NAME
        rf.valid_duplexes   = ['', '-', '+', 'split', 'off']
        rf.valid_tmodes     = ['', 'Tone', 'TSQL', 'DTCS', 'Cross']
        rf.valid_cross_modes = [
            'Tone->Tone', 'DTCS->', '->DTCS',
            'Tone->DTCS', 'DTCS->Tone', '->Tone', 'DTCS->DTCS']
        rf.valid_skips      = ['', 'S']
        rf.valid_dtcs_codes = self.DTCS_CODES
        rf.memory_bounds    = (1, self.CHANNELS)
        rf.valid_power_levels = self.POWER_LEVELS
        rf.valid_bands      = self.VALID_BANDS
        rf.valid_tuning_steps = self.STEPS
        return rf

    # ── Clone I/O ─────────────────────────────────────────────────────────────

    def sync_in(self):
        try:
            data = _download_5rh(self)
        except errors.RadioError:
            raise
        except Exception:
            LOG.exception('Unexpected error during download')
            raise errors.RadioError('Unexpected error communicating with radio')
        self._mmap = memmap.MemoryMapBytes(data)

    def sync_out(self):
        try:
            _upload_5rh(self)
        except errors.RadioError:
            raise
        except Exception:
            LOG.exception('Unexpected error during upload')
            raise errors.RadioError('Unexpected error communicating with radio')

    def process_mmap(self):
        pass  # raw byte access; no bitwise parse needed

    def load_mmap(self, filename):
        with open(filename, 'rb') as f:
            self._mmap = memmap.MemoryMapBytes(f.read())

    def save_mmap(self, filename):
        with open(filename, 'wb') as f:
            f.write(self._mmap.get_byte_compatible())

    def get_raw_memory(self, number):
        return repr(_read_chn_raw(self._mmap, number - 1))

    # ── Memory access ─────────────────────────────────────────────────────────

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
        tx_freq  = _decode_freq(raw[4:8])

        if all(b == 0xFF for b in raw[4:8]):
            mem.duplex = 'off'
            mem.offset = 0
        elif tx_freq == mem.freq:
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
        rx_mode, rx_val, rx_pol = _decode_tone(raw[8],  raw[9])
        chirp_common.split_tone_decode(
            mem, (tx_mode, tx_val, tx_pol), (rx_mode, rx_val, rx_pol))

        # Flags (byte 16)
        f16 = raw[16]
        power_idx = (f16 >> 6) & 0x03
        try:
            mem.power = self.POWER_LEVELS[power_idx]
        except IndexError:
            mem.power = self.POWER_LEVELS[0]
        is_narrow = bool((f16 >> 4) & 0x03)
        mem.mode = 'NFM' if is_narrow else 'FM'
        if chirp_common.in_range(mem.freq, [(108_000_000, 136_000_000)]):
            mem.mode = 'AM'

        # Skip flag (from scan-add bitmap at ADDR_SCAN_FLAGS)
        scan_byte = idx // 8
        scan_bit  = idx % 8
        scan_val  = _mb(self._mmap, ADDR_SCAN_FLAGS + scan_byte)
        mem.skip  = '' if ((scan_val >> scan_bit) & 1) == 0 else 'S'

        # Name (bytes 32-47, GB2312)
        mem.name = _decode_name(raw[32:48])

        # Extra settings
        mem.extra = RadioSettingGroup('Extra', 'extra')

        f17 = raw[17]
        f19 = raw[19]
        f20 = raw[20]

        rs = RadioSetting('busylock', 'Busy Channel Lockout',
                          RadioSettingValueList(LIST_BCL,
                                               current_index=(f19 >> 6) & 0x03))
        mem.extra.append(rs)

        rs = RadioSetting('txdis', 'TX Disable',
                          RadioSettingValueBoolean(bool((f19 >> 5) & 1)))
        mem.extra.append(rs)

        rs = RadioSetting('talkaround', 'Talk Around',
                          RadioSettingValueBoolean(bool(f16 & 1)))
        mem.extra.append(rs)

        rs = RadioSetting('compand', 'Compander',
                          RadioSettingValueBoolean(bool((f20 >> 5) & 1)))
        mem.extra.append(rs)

        rs = RadioSetting('scram', 'Scramble',
                          RadioSettingValueBoolean(bool((f20 >> 4) & 1)))
        mem.extra.append(rs)

        signal_idx = (raw[18] >> 5) & 0x07
        if signal_idx < len(LIST_SIGNAL):
            rs = RadioSetting('signaltype', 'Signal Type',
                              RadioSettingValueList(LIST_SIGNAL,
                                                   current_index=signal_idx))
            mem.extra.append(rs)

        return mem

    def set_memory(self, mem):
        idx = mem.number - 1
        mmap = self._mmap

        if mem.empty:
            raw = bytearray(_CHN_SIZE)
            _write_chn_raw(mmap, idx, bytes(raw))
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
        raw[8],  raw[9]  = _encode_tone(rxmode, rxtone, rxpol)

        # Byte 16: power + bandwidth + offset dir + freq invert + talk around
        power_idx = self.POWER_LEVELS.index(mem.power) if mem.power else 0
        f16 = (power_idx & 0x03) << 6
        if mem.mode == 'NFM':
            f16 |= 0x10
        raw[16] = f16

        # Extra settings
        f17 = f19 = f20 = 0
        if mem.extra:
            for rs in mem.extra:
                name = rs.get_name()
                val  = rs.value
                if name == 'busylock':
                    f19 |= (int(val) & 0x03) << 6
                elif name == 'txdis':
                    f19 |= (1 << 5) if bool(val) else 0
                elif name == 'talkaround':
                    raw[16] |= 1 if bool(val) else 0
                elif name == 'compand':
                    f20 |= (1 << 5) if bool(val) else 0
                elif name == 'scram':
                    f20 |= (1 << 4) if bool(val) else 0
                elif name == 'signaltype':
                    sig_idx = LIST_SIGNAL.index(str(val)) if str(val) in LIST_SIGNAL else 0
                    raw[18] |= (sig_idx & 0x07) << 5
        raw[17] = f17
        raw[19] = f19
        raw[20] = f20

        # Name
        enc_name = _encode_name(mem.name, 16)
        for i, b in enumerate(enc_name):
            raw[32 + i] = b

        _write_chn_raw(mmap, idx, bytes(raw))
        _set_chn_used(mmap, idx, True)

        # Scan add flag (skip)
        scan_byte = idx // 8
        scan_bit  = idx % 8
        bv = _mb(mmap, ADDR_SCAN_FLAGS + scan_byte)
        if mem.skip == 'S':
            bv |= (1 << scan_bit)
        else:
            bv &= ~(1 << scan_bit)
        _mwb(mmap, ADDR_SCAN_FLAGS + scan_byte, bv)

    # ── Settings ──────────────────────────────────────────────────────────────

    def _s(self, offset):
        """Read settings byte at relative offset as int."""
        return _mb(self._mmap, ADDR_SETTINGS + offset)

    def _sw(self, offset, value):
        """Write settings byte."""
        _mwb(self._mmap, ADDR_SETTINGS + offset, value)

    def get_settings(self):
        s = [self._s(i) for i in range(128)]

        basic = RadioSettingGroup('basic', 'Basic Settings')
        gps   = RadioSettingGroup('gps',   'GPS Settings')
        bt    = RadioSettingGroup('bt',    'Bluetooth Settings')
        top   = RadioSettings(basic, gps, bt)

        def _add(group, path, label, val_obj):
            group.append(RadioSetting(path, label, val_obj))

        # Work mode
        cha_mode = s[0] if s[0] < 2 else 0
        chb_mode = s[1] if s[1] < 2 else 0
        _add(basic, 'settings.chaworkmode', 'Channel A Work Mode',
             RadioSettingValueList(LIST_WORKMODE, current_index=cha_mode))
        _add(basic, 'settings.chbworkmode', 'Channel B Work Mode',
             RadioSettingValueList(LIST_WORKMODE, current_index=chb_mode))

        # Channel numbers (stored big-endian u16)
        cha_num = (s[2] << 8) | s[3]
        chb_num = (s[4] << 8) | s[5]
        _add(basic, 'settings.chanum',
             'Channel A Number',
             RadioSettingValueInteger(1, _MAX_CHN,
                                      max(1, min(cha_num, _MAX_CHN))))
        _add(basic, 'settings.chbnum',
             'Channel B Number',
             RadioSettingValueInteger(1, _MAX_CHN,
                                      max(1, min(chb_num, _MAX_CHN))))

        # Backlight
        bl_raw = s[8]
        bl_idx = max(0, bl_raw - 4) if bl_raw >= 4 else 0
        bl_idx = min(bl_idx, len(LIST_BACKLIGHT) - 1)
        _add(basic, 'settings.backlight', 'Backlight Time',
             RadioSettingValueList(LIST_BACKLIGHT, current_index=bl_idx))

        _add(basic, 'settings.blightlv', 'Backlight Level',
             RadioSettingValueList(LIST_BLIGHT_LV,
                                   current_index=max(0, min(s[9] - 1, 4))))

        # Dual standby / squelch
        _add(basic, 'settings.dualmode', 'Dual Standby',
             RadioSettingValueBoolean(bool(s[11])))

        sq_idx = s[13] if s[13] < 10 else 5
        _add(basic, 'settings.squelch', 'Squelch',
             RadioSettingValueList(LIST_SQUELCH, current_index=sq_idx))

        # VOX
        vox_lv = max(0, s[14] - 1)
        _add(basic, 'settings.voxlv', 'VOX Level (0=off)',
             RadioSettingValueInteger(0, 9, min(vox_lv, 9)))

        # APO / TOT
        apo_idx = s[20] if s[20] <= 60 else 0
        _add(basic, 'settings.apo', 'Auto Power Off',
             RadioSettingValueList(LIST_APO, current_index=apo_idx))

        tot_idx = s[21] if s[21] < len(LIST_TOT) else 0
        _add(basic, 'settings.tot', 'TX Timeout Timer',
             RadioSettingValueList(LIST_TOT, current_index=tot_idx))

        # Byte 32 packed flags
        b32 = s[32]
        _add(basic, 'settings.voxsw', 'VOX Switch',
             RadioSettingValueBoolean(bool((b32 >> 7) & 1)))
        _add(basic, 'settings.aprsw', 'APRS Switch',
             RadioSettingValueBoolean(bool((b32 >> 6) & 1)))
        _add(basic, 'settings.lonework', 'Lone Worker',
             RadioSettingValueBoolean(bool((b32 >> 5) & 1)))
        voice_idx = (b32 >> 2) & 0x03
        _add(basic, 'settings.voice', 'Voice Prompt',
             RadioSettingValueList(LIST_VOICE, current_index=min(voice_idx, 2)))
        _add(basic, 'settings.busylock', 'Busy Channel Lockout',
             RadioSettingValueBoolean(bool(b32 & 0x03)))

        # Byte 33: key lock / auto key
        b33 = s[33]
        _add(basic, 'settings.keylock', 'Key Lock',
             RadioSettingValueBoolean(bool((b33 >> 7) & 1)))

        # Byte 34: tone / end tone
        b34 = s[34]
        _add(basic, 'settings.beep', 'Beep Tone',
             RadioSettingValueBoolean(bool((b34 >> 7) & 1)))

        # Byte 37: language / power-on face
        b37 = s[37]
        _add(basic, 'settings.langsel', 'Language',
             RadioSettingValueList(['Chinese', 'English'],
                                   current_index=(b37 >> 2) & 1))

        # Byte 38: NOAA / FM
        b38 = s[38]
        _add(basic, 'settings.noaa', 'NOAA Weather',
             RadioSettingValueBoolean(bool((b38 >> 4) & 1)))
        _add(basic, 'settings.fminter', 'FM Radio',
             RadioSettingValueBoolean(bool((b38 >> 2) & 1)))

        # ── GPS ───────────────────────────────────────────────────────────────
        b35 = s[35]
        _add(gps, 'settings.gpssw', 'GPS On',
             RadioSettingValueBoolean(bool((b35 >> 7) & 1)))
        gpsmode_idx = (b35 >> 5) & 0x03
        _add(gps, 'settings.gpsmode', 'GPS Mode',
             RadioSettingValueList(LIST_GPS_MODE,
                                   current_index=min(gpsmode_idx, 2)))
        _add(gps, 'settings.gpsshare', 'GPS Share',
             RadioSettingValueBoolean(bool((b35 >> 4) & 1)))
        _add(gps, 'settings.gpsreq', 'GPS Request',
             RadioSettingValueBoolean(bool((b35 >> 3) & 1)))
        _add(gps, 'settings.gpszone', 'GPS Zone',
             RadioSettingValueInteger(0, 9, min(s[24], 9)))

        # ── Bluetooth ─────────────────────────────────────────────────────────
        b36 = s[36]
        _add(bt, 'settings.bluetooth', 'Bluetooth On',
             RadioSettingValueBoolean(bool((b36 >> 7) & 1)))
        btpair_idx = (b36 >> 5) & 0x03
        _add(bt, 'settings.btpair', 'BT Pair Mode',
             RadioSettingValueList(LIST_BT_PAIR,
                                   current_index=min(btpair_idx, 2)))
        _add(bt, 'settings.bthold', 'BT Hold Time (×100ms)',
             RadioSettingValueInteger(0, 255, s[40]))

        # BT password (4 ASCII bytes at offset 44)
        bt_pwd = bytes(s[44:48]).decode('ascii', errors='replace').rstrip('\x00\xff')
        _add(bt, 'settings.btpassword', 'BT Password',
             RadioSettingValueString(0, 4, bt_pwd))

        # Radio name (GB2312, bytes 80-95)
        radio_name = _decode_name(bytes(s[80:96]))
        _add(basic, 'settings.radioname', 'Radio Name',
             RadioSettingValueString(0, 8, radio_name, False, _CHARSET))

        return top

    def set_settings(self, settings):
        for group in settings:
            if isinstance(group, RadioSettingGroup):
                for rs in group:
                    if not isinstance(rs, RadioSetting):
                        continue
                    self._apply_setting(rs)
            elif isinstance(settings, RadioSetting):
                self._apply_setting(settings)

    def _apply_setting(self, rs):
        name = rs.get_name()
        val  = rs.value

        def _b(n):
            return self._s(n)

        def _wb(n, v):
            self._sw(n, v)

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
        elif name == 'settings.backlight':
            # index 0 = Off (raw 0), 1-5 = 5s..Always (raw 4-9 or similar)
            idx = int(val)
            _wb(8, idx + 4 if idx > 0 else 0)
        elif name == 'settings.blightlv':
            _wb(9, int(val) + 1)
        elif name == 'settings.dualmode':
            _wb(11, 1 if bool(val) else 0)
        elif name == 'settings.squelch':
            _wb(13, int(val))
        elif name == 'settings.voxlv':
            _wb(14, int(val) + 1)
        elif name == 'settings.apo':
            _wb(20, int(val))
        elif name == 'settings.tot':
            _wb(21, int(val))
        elif name == 'settings.gpszone':
            _wb(24, int(val))
        elif name in ('settings.voxsw', 'settings.aprsw', 'settings.lonework',
                      'settings.voice', 'settings.busylock'):
            b32 = _b(32)
            if name == 'settings.voxsw':
                b32 = (b32 & 0x7F) | (0x80 if bool(val) else 0)
            elif name == 'settings.aprsw':
                b32 = (b32 & 0xBF) | (0x40 if bool(val) else 0)
            elif name == 'settings.lonework':
                b32 = (b32 & 0xDF) | (0x20 if bool(val) else 0)
            elif name == 'settings.voice':
                b32 = (b32 & 0xF3) | ((int(val) & 0x03) << 2)
            elif name == 'settings.busylock':
                b32 = (b32 & 0xFC) | (1 if bool(val) else 0)
            _wb(32, b32)
        elif name == 'settings.keylock':
            b33 = _b(33)
            _wb(33, (b33 & 0x7F) | (0x80 if bool(val) else 0))
        elif name == 'settings.beep':
            b34 = _b(34)
            _wb(34, (b34 & 0x7F) | (0x80 if bool(val) else 0))
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
        elif name in ('settings.bluetooth', 'settings.btpair'):
            b36 = _b(36)
            if name == 'settings.bluetooth':
                b36 = (b36 & 0x7F) | (0x80 if bool(val) else 0)
            elif name == 'settings.btpair':
                b36 = (b36 & 0x9F) | ((int(val) & 0x03) << 5)
            _wb(36, b36)
        elif name == 'settings.langsel':
            b37 = _b(37)
            _wb(37, (b37 & 0xFB) | ((int(val) & 1) << 2))
        elif name == 'settings.noaa':
            b38 = _b(38)
            _wb(38, (b38 & 0xEF) | (0x10 if bool(val) else 0))
        elif name == 'settings.fminter':
            b38 = _b(38)
            _wb(38, (b38 & 0xFB) | (0x04 if bool(val) else 0))
        elif name == 'settings.bthold':
            _wb(40, int(val))
        elif name == 'settings.btpassword':
            pwd = str(val).encode('ascii', errors='replace')[:4].ljust(4, b'\x00')
            for i, b in enumerate(pwd):
                _wb(44 + i, b)
        elif name == 'settings.radioname':
            enc = _encode_name(str(val), 16)
            for i, b in enumerate(enc):
                _wb(80 + i, b)
        else:
            LOG.debug('5RH: unhandled setting %s', name)
