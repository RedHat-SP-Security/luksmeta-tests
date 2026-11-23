#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /Security/crafted-header-slot-range
#   Description: Test that crafted out-of-gap slot ranges in luksmeta
#                header do not corrupt LUKS1 encrypted payload
#   Author: Adam Prikryl <aprikryl@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2026 Red Hat, Inc. All rights reserved.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGES="luksmeta cryptsetup util-linux xfsprogs python3"
LUKS_PW=luks
DEVNAME="luks-${RANDOM}"
CRAFT_UUID="deadbeef-dead-beef-dead-beefdeadbeef"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm --all
        rlRun "set -o pipefail"

        rlRun "tmp=\$(mktemp -d)" 0 "Create tmp directory"
        rlRun "pushd \${tmp}"

        rlRun "LUKS_DEVICE=\$(realpath luks-device)"
        rlRun "fallocate -l512m ${LUKS_DEVICE}"
        rlRun "echo ${LUKS_PW} | cryptsetup luksFormat --type luks1 --batch-mode --force-password --pbkdf-force-iterations 1000 --key-size 512 ${LUKS_DEVICE}"
        rlRun "cryptsetup open ${LUKS_DEVICE} ${DEVNAME} <<< ${LUKS_PW}" 0 "Open LUKS device"
        rlRun "mkfs.xfs /dev/mapper/${DEVNAME}" 0 "Creating xfs filesystem"
        rlRun "mount /dev/mapper/${DEVNAME} /mnt" 0 "Mounting device"
        rlRun "echo redhat > /mnt/luks1-test" 0 "Creating test file"
        rlRun "umount /mnt" 0 "Umounting the device"
        rlRun "cryptsetup close ${DEVNAME}" 0 "Closing the LUKS device"

        PAYLOAD_OFFSET_SECTORS=$(cryptsetup luksDump ${LUKS_DEVICE} | awk '/Payload offset:/{print $3}')
        PAYLOAD_OFFSET=$((PAYLOAD_OFFSET_SECTORS * 512))
        rlLog "Payload offset: ${PAYLOAD_OFFSET} bytes (${PAYLOAD_OFFSET_SECTORS} sectors)"

        cat > patch_header.py << 'PYEOF'
#!/usr/bin/env python3
"""Patch luksmeta header to craft out-of-gap slot ranges for CVE testing.

luksmeta on-disk header layout (272 bytes total):
  bytes  0-7:   magic "LUKSMETA"
  bytes  8-11:  version (big-endian uint32, value 1)
  bytes 12-15:  CRC32C of header (big-endian uint32)
  bytes 16-271: 8 slots x 32 bytes each:
    bytes 0-15:  UUID (16 bytes, all-zero = empty)
    bytes 16-19: offset from hole start (big-endian uint32)
    bytes 20-23: data length (big-endian uint32)
    bytes 24-27: CRC32C of slot data (big-endian uint32)
    bytes 28-31: reserved
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

    elif action == 'patch':
        slot = int(sys.argv[3])
        new_offset = int(sys.argv[4])
        new_length = int(sys.argv[5])
        search_limit = int(sys.argv[6])

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
        struct.pack_into('>I', header, s + 24, 0x12345678)

        struct.pack_into('>I', header, 12, 0)
        new_crc = crc32c(bytes(header))
        struct.pack_into('>I', header, 12, new_crc)

        with open(device, 'r+b') as f:
            f.seek(pos)
            f.write(header)

        print("Patched slot %d: offset=%d length=%d header_pos=%d crc=0x%08x"
              % (slot, new_offset, new_length, pos, new_crc))

if __name__ == '__main__':
    main()
PYEOF
    rlPhaseEnd

    rlPhaseStartTest "Wipe with out-of-gap slot range does not corrupt payload"
        rlRun "luksmeta init -f -d ${LUKS_DEVICE}" 0 "Initialize luksmeta"

        HOLE_OFFSET=$(python3 patch_header.py find ${LUKS_DEVICE} ${PAYLOAD_OFFSET})
        GAP_SIZE=$((PAYLOAD_OFFSET - HOLE_OFFSET))
        rlLog "Hole offset: ${HOLE_OFFSET}, gap size: ${GAP_SIZE}, payload: ${PAYLOAD_OFFSET}"

        # Craft slot 2 with offset+length extending 4096 bytes past the gap into payload
        CRAFT_OFFSET=4096
        CRAFT_LENGTH=$((GAP_SIZE - 4096 + 4096))
        rlRun "python3 patch_header.py patch ${LUKS_DEVICE} 2 ${CRAFT_OFFSET} ${CRAFT_LENGTH} ${PAYLOAD_OFFSET}" 0 \
            "Craft slot 2 with range extending past gap into encrypted payload"

        rlRun "luksmeta wipe -d ${LUKS_DEVICE} -s 2 -u ${CRAFT_UUID} -f" 0,1,73,74 \
            "Wipe crafted slot 2 (should be rejected or harmless)"

        rlRun "cryptsetup open ${LUKS_DEVICE} ${DEVNAME} <<< ${LUKS_PW}" 0 "Open LUKS device"
        rlRun "mount /dev/mapper/${DEVNAME} /mnt" 0 "Mounting the device for verification"
        rlRun "test \$(cat /mnt/luks1-test) = redhat" 0 "Verify encrypted payload not corrupted after wipe"
        rlRun "umount /mnt" 0 "Umounting the device"
        rlRun "cryptsetup close ${DEVNAME}" 0 "Closing the LUKS device"
    rlPhaseEnd

    rlPhaseStartTest "Load with out-of-gap slot range fails gracefully"
        rlRun "luksmeta init -f -d ${LUKS_DEVICE}" 0 "Re-initialize luksmeta"

        HOLE_OFFSET=$(python3 patch_header.py find ${LUKS_DEVICE} ${PAYLOAD_OFFSET})
        GAP_SIZE=$((PAYLOAD_OFFSET - HOLE_OFFSET))
        CRAFT_OFFSET=4096
        CRAFT_LENGTH=$((GAP_SIZE - 4096 + 4096))
        rlRun "python3 patch_header.py patch ${LUKS_DEVICE} 2 ${CRAFT_OFFSET} ${CRAFT_LENGTH} ${PAYLOAD_OFFSET}" 0 \
            "Craft slot 2 for load test"

        rlRun -s "luksmeta load -d ${LUKS_DEVICE} -s 2 -u ${CRAFT_UUID}" 1,73,74 \
            "Load from crafted slot 2 should fail gracefully"
        rlRun "rm -f \$rlRun_LOG" 0

        rlRun "cryptsetup open ${LUKS_DEVICE} ${DEVNAME} <<< ${LUKS_PW}" 0 "Open LUKS device"
        rlRun "mount /dev/mapper/${DEVNAME} /mnt" 0 "Mounting the device for verification"
        rlRun "test \$(cat /mnt/luks1-test) = redhat" 0 "Verify encrypted payload not corrupted after load"
        rlRun "umount /mnt" 0 "Umounting the device"
        rlRun "cryptsetup close ${DEVNAME}" 0 "Closing the LUKS device"
    rlPhaseEnd

    rlPhaseStartTest "Wrapping slot endpoint does not misposition header rewrite"
        rlRun "luksmeta init -f -d ${LUKS_DEVICE}" 0 "Re-initialize luksmeta"

        # Save valid metadata to slot 1 for later integrity check
        rlRun "dd if=/dev/urandom of=slot1-data bs=4096 count=1" 0 "Create 4KB data for slot 1"
        rlRun "luksmeta save -d ${LUKS_DEVICE} -s 1 -u 70e213ff-61fb-4dae-847e-d67b593f230b < slot1-data" 0 \
            "Save valid entry to slot 1"

        HOLE_OFFSET=$(python3 patch_header.py find ${LUKS_DEVICE} ${PAYLOAD_OFFSET})
        GAP_SIZE=$((PAYLOAD_OFFSET - HOLE_OFFSET))

        # Craft slot 3 with large offset+length that could wrap uint32 or misposition seeks
        CRAFT_OFFSET=$((GAP_SIZE - 4096))
        CRAFT_LENGTH=8192
        rlRun "python3 patch_header.py patch ${LUKS_DEVICE} 3 ${CRAFT_OFFSET} ${CRAFT_LENGTH} ${PAYLOAD_OFFSET}" 0 \
            "Craft slot 3 with wrapping endpoint"

        rlRun "luksmeta wipe -d ${LUKS_DEVICE} -s 3 -u ${CRAFT_UUID} -f" 0,1,73,74 \
            "Wipe crafted slot 3 (wrapping endpoint)"

        # Verify the luksmeta header is still readable and slot 1 data intact
        rlRun "luksmeta load -d ${LUKS_DEVICE} -s 1 -u 70e213ff-61fb-4dae-847e-d67b593f230b > slot1-verify" 0 \
            "Load slot 1 after wrapping wipe"
        rlRun "diff slot1-data slot1-verify" 0 "Verify slot 1 metadata not corrupted by mispositioned header rewrite"

        rlRun "cryptsetup open ${LUKS_DEVICE} ${DEVNAME} <<< ${LUKS_PW}" 0 "Open LUKS device"
        rlRun "mount /dev/mapper/${DEVNAME} /mnt" 0 "Mounting the device for verification"
        rlRun "test \$(cat /mnt/luks1-test) = redhat" 0 "Verify encrypted payload not corrupted"
        rlRun "umount /mnt" 0 "Umounting the device"
        rlRun "cryptsetup close ${DEVNAME}" 0 "Closing the LUKS device"
    rlPhaseEnd

    rlPhaseStartCleanup
        rlRun "umount /mnt ||:" 0 "Umounting the device, if mounted"
        rlRun "cryptsetup close ${DEVNAME} ||:" 0 "Closing the LUKS device, if opened"
        rlRun "popd"
        rlRun "rm -r \${tmp}" 0 "Remove tmp directory"
    rlPhaseEnd
rlJournalEnd
