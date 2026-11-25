#!/usr/bin/env python3
"""Patch luksmeta header to craft slot ranges for CVE testing.

luksmeta on-disk header layout (272 bytes total, integers big-endian):
  bytes  0-7:   magic "LUKSMETA"
  bytes  8-11:  version (uint32, value 1)
  bytes 12-15:  CRC32C of header (uint32, computed with the field zeroed)
  bytes 16-271: 8 slots x 32 bytes each:
    bytes  0-15:  UUID (16 bytes, all-zero = empty slot)
    bytes 16-19:  offset from hole start (uint32)
    bytes 20-23:  data length (uint32)
    bytes 24-27:  CRC32C of slot data (uint32)
    bytes 28-31:  reserved

Actions:
  find DEVICE SEARCH_LIMIT
      Print the byte offset of the luksmeta header ("LUKSMETA" magic).
  crc FILE
      Print the CRC32C of FILE's contents, for crafting a slot data
      CRC that matches bytes actually stored on the device.
  patch DEVICE SLOT OFFSET LENGTH SEARCH_LIMIT [DATACRC]
      Patch SLOT with OFFSET/LENGTH (and DATACRC, default 0x12345678),
      recomputing the header CRC32C so the header passes validation.
"""
import struct
import sys

HEADER_SIZE = 272
MAGIC = b'LUKSMETA'
SLOT_SIZE = 32

def crc32c(data):
    """Compute CRC32C (Castagnoli) checksum."""
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
        table.append(crc)
    crc = 0xFFFFFFFF
    for b in data:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF

def main():
    action = sys.argv[1]
    device = sys.argv[2]

    if action == 'find':
        search_limit = int(sys.argv[3])
        with open(device, 'rb') as f:
            data = f.read(search_limit)
        pos = data.find(MAGIC)
        if pos < 0:
            print("LUKSMETA header not found", file=sys.stderr)
            sys.exit(1)
        print(pos)

    elif action == 'crc':
        with open(device, 'rb') as f:
            print('0x%08x' % crc32c(f.read()))

    elif action == 'patch':
        slot = int(sys.argv[3])
        new_offset = int(sys.argv[4])
        new_length = int(sys.argv[5])
        search_limit = int(sys.argv[6])
        data_crc = int(sys.argv[7], 0) if len(sys.argv) > 7 else 0x12345678

        with open(device, 'rb') as f:
            data = f.read(search_limit)
        pos = data.find(MAGIC)
        assert pos >= 0, "LUKSMETA header not found"

        header = bytearray(data[pos:pos + HEADER_SIZE])
        s = 16 + slot * SLOT_SIZE

        if header[s:s + 16] == b'\x00' * 16:
            header[s:s + 16] = bytes.fromhex('deadbeefdeadbeefdeadbeefdeadbeef')

        struct.pack_into('>I', header, s + 16, new_offset)
        struct.pack_into('>I', header, s + 20, new_length)
        struct.pack_into('>I', header, s + 24, data_crc)

        struct.pack_into('>I', header, 12, 0)
        new_crc = crc32c(bytes(header))
        struct.pack_into('>I', header, 12, new_crc)

        with open(device, 'r+b') as f:
            f.seek(pos)
            f.write(header)

        print("Patched slot %d: offset=%d length=%d datacrc=0x%08x header_pos=%d crc=0x%08x"
              % (slot, new_offset, new_length, data_crc, pos, new_crc))

if __name__ == '__main__':
    main()
