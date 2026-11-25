#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /Security/crafted-header-slot-range
#   Description: Test that crafted out-of-gap slot ranges in luksmeta
#                headers are rejected (exit 72, "appears corrupt")
#                without corrupting the LUKS1 encrypted payload
#   Author: Adam Prikryl <aprikryl@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2026 Red Hat, Inc. All rights reserved.
#
#   This copyrighted material is made available to anyone wishing to use,
#   modify, copy, or redistribute it subject to the terms and conditions
#   of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
#   02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
# NOTE on expected exit codes: when read_header() rejects a crafted
# header with -EINVAL, the luksmeta CLI reports "LUKSMeta data appears
# corrupt" and exits with EX_OSFILE (72). Vulnerable code accepts the
# crafted header instead and performs the (misplaced) operation, so
# these phases must expect exactly 72 on fixed code.
#
# NOTE on crafting values: read_header() checks, per occupied slot,
# offset > sizeof(lm_t) (= 272) and length <= gap - 4096 (the page-
# aligned lm_t header area), both before and after the fix. The fix
# adds offset + length <= gap (computed in uint64_t). A craft that
# actually exercises the missing check must pass the two pre-existing
# checks while exceeding the gap: offset=8192 with length=gap-4096
# ends at gap+4096.

. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGES="luksmeta cryptsetup util-linux xfsprogs"
LUKS_PW=luks
DEVNAME="luks-${RANDOM}"
CRAFT_UUID="deadbeef-dead-beef-dead-beefdeadbeef"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm --all
        # python3 is not a real package name on all distros (e.g. RHEL 8
        # ships it as python36/platform-python), so check the interpreter
        # itself instead of the rpm. Installation is handled by the
        # "recommend" list in main.fmf.
        rlRun "python3 --version" 0 "Check python3 interpreter is available"
        rlRun "set -o pipefail"

        # Test case directory (patch_header.py lives next to runtest.sh);
        # captured before pushd into the tmp directory.
        TESTDIR=$(pwd)

        rlRun "tmp=\$(mktemp -d)" 0 "Create tmp directory"
        rlRun "pushd \${tmp}"

        # Unique mountpoint under this run's tmp directory, so concurrent
        # runs in the same mount namespace cannot unmount each other's
        # filesystems or verify the wrong device.
        MOUNTPOINT="${tmp}/mnt"
        rlRun "mkdir -p ${MOUNTPOINT}" 0 "Create unique mountpoint"

        rlRun "LUKS_DEVICE=\$(realpath luks-device)"
        rlRun "fallocate -l512m ${LUKS_DEVICE}"
        rlRun "echo ${LUKS_PW} | cryptsetup luksFormat --type luks1 --batch-mode --force-password --pbkdf-force-iterations 1000 --key-size 512 ${LUKS_DEVICE}"
        rlRun "cryptsetup open ${LUKS_DEVICE} ${DEVNAME} <<< ${LUKS_PW}" 0 "Open LUKS device"
        rlRun "mkfs.xfs /dev/mapper/${DEVNAME}" 0 "Creating xfs filesystem"
        rlRun "mount /dev/mapper/${DEVNAME} ${MOUNTPOINT}" 0 "Mounting device"
        rlRun "echo redhat > ${MOUNTPOINT}/luks1-test" 0 "Creating test file"
        rlRun "umount ${MOUNTPOINT}" 0 "Umounting the device"
        rlRun "cryptsetup close ${DEVNAME}" 0 "Closing the LUKS device"

        PAYLOAD_OFFSET_SECTORS=$(cryptsetup luksDump ${LUKS_DEVICE} | awk '/Payload offset:/{print $3}')
        PAYLOAD_OFFSET=$((PAYLOAD_OFFSET_SECTORS * 512))
        rlLog "Payload offset: ${PAYLOAD_OFFSET} bytes (${PAYLOAD_OFFSET_SECTORS} sectors)"

    rlPhaseEnd

    rlPhaseStartTest "Positive control: in-bounds crafted slot is accepted"
        rlRun "luksmeta init -f -d ${LUKS_DEVICE}" 0 "Initialize luksmeta"

        HOLE_OFFSET=$(python3 ${TESTDIR}/patch_header.py find ${LUKS_DEVICE} ${PAYLOAD_OFFSET})
        GAP_SIZE=$((PAYLOAD_OFFSET - HOLE_OFFSET))
        rlLog "Hole offset: ${HOLE_OFFSET}, gap size: ${GAP_SIZE}, payload: ${PAYLOAD_OFFSET}"

        # In-bounds craft: slot 4 at offset 8192 (past the page-aligned lm_t
        # header area) holding 4096 bytes of real data with a matching data
        # CRC. Must be accepted by fixed and vulnerable code alike; it proves
        # the patching machinery produces headers that pass read_header().
        rlRun "dd if=/dev/urandom of=ctrl-data bs=4096 count=1" 0 "Create 4KB control data"
        rlRun "dd if=ctrl-data of=${LUKS_DEVICE} bs=1 seek=$((HOLE_OFFSET + 8192)) conv=notrunc" 0 \
            "Write control data into the gap at offset 8192"
        CTRL_CRC=$(python3 ${TESTDIR}/patch_header.py crc ctrl-data)
        rlRun "python3 ${TESTDIR}/patch_header.py patch ${LUKS_DEVICE} 4 8192 4096 ${PAYLOAD_OFFSET} ${CTRL_CRC}" 0 \
            "Craft in-bounds slot 4 with matching data CRC"
        rlRun "luksmeta load -d ${LUKS_DEVICE} -s 4 -u ${CRAFT_UUID} > ctrl-verify" 0 \
            "Load from in-bounds crafted slot 4 (must succeed)"
        rlRun "diff ctrl-data ctrl-verify" 0 "Verify control data round-trips"
    rlPhaseEnd

    rlPhaseStartTest "Wipe with out-of-gap slot range is rejected"
        # Nuke is required here: the positive-control phase leaves a valid
        # header (crafted slot 4 at offset 8192) behind, and init -f is a
        # no-op on a valid header (luksmeta_init returns -EALREADY, which
        # cmd_init maps to exit 0). Without the nuke, the slot 1 placement
        # below only works because the control slot happens to sit at 8192
        # rather than 4096. The load and wrapping phases are unaffected:
        # their headers are corrupt at that point, so init genuinely
        # rewrites.
        rlRun "luksmeta init -f -n -d ${LUKS_DEVICE}" 0 "Nuke and re-initialize luksmeta"

        HOLE_OFFSET=$(python3 ${TESTDIR}/patch_header.py find ${LUKS_DEVICE} ${PAYLOAD_OFFSET})
        GAP_SIZE=$((PAYLOAD_OFFSET - HOLE_OFFSET))

        # Save a valid entry to slot 1 to verify it is not affected. On a
        # fresh header the allocator places it at offset 4096 from the hole.
        rlRun "dd if=/dev/urandom of=slot1-data bs=4096 count=1" 0 "Create 4KB data for slot 1"
        rlRun "luksmeta save -d ${LUKS_DEVICE} -s 1 -u 70e213ff-61fb-4dae-847e-d67b593f230b < slot1-data" 0 \
            "Save valid entry to slot 1"

        # Out-of-gap craft: passes both pre-existing checks (offset 8192 > 272,
        # length gap-4096 <= maxlen), endpoint gap+4096 lies 4096 bytes past
        # the gap in the encrypted payload. Fixed code rejects the header
        # (-EINVAL -> exit 72); vulnerable code zeroes the payload range.
        CRAFT_OFFSET=8192
        CRAFT_LENGTH=$((GAP_SIZE - 4096))
        rlRun "python3 ${TESTDIR}/patch_header.py patch ${LUKS_DEVICE} 2 ${CRAFT_OFFSET} ${CRAFT_LENGTH} ${PAYLOAD_OFFSET}" 0 \
            "Craft slot 2 with range extending past gap into encrypted payload"

        rlRun -s "luksmeta wipe -d ${LUKS_DEVICE} -s 2 -u ${CRAFT_UUID} -f" 72 \
            "Wipe crafted slot 2 (must be rejected as corrupt)"
        rlAssertGrep "appears corrupt" "${rlRun_LOG}"
        rlRun "rm -f \$rlRun_LOG" 0

        # While the crafted slot is in the header, luksmeta load fails for
        # ALL slots, so verify slot 1's raw bytes on disk directly.
        rlRun "dd if=${LUKS_DEVICE} of=slot1-raw bs=1 skip=$((HOLE_OFFSET + 4096)) count=4096" 0 \
            "Read slot 1 raw bytes from device"
        rlRun "diff slot1-data slot1-raw" 0 "Verify slot 1 metadata not corrupted"

        rlRun "cryptsetup open ${LUKS_DEVICE} ${DEVNAME} <<< ${LUKS_PW}" 0 "Open LUKS device"
        rlRun "mount /dev/mapper/${DEVNAME} ${MOUNTPOINT}" 0 "Mounting the device for verification"
        rlRun "test \$(cat ${MOUNTPOINT}/luks1-test) = redhat" 0 "Verify encrypted payload not corrupted after wipe"
        rlRun "umount ${MOUNTPOINT}" 0 "Umounting the device"
        rlRun "cryptsetup close ${DEVNAME}" 0 "Closing the LUKS device"
    rlPhaseEnd

    rlPhaseStartTest "Load with out-of-gap slot range is rejected"
        rlRun "luksmeta init -f -d ${LUKS_DEVICE}" 0 "Re-initialize luksmeta"

        HOLE_OFFSET=$(python3 ${TESTDIR}/patch_header.py find ${LUKS_DEVICE} ${PAYLOAD_OFFSET})
        GAP_SIZE=$((PAYLOAD_OFFSET - HOLE_OFFSET))

        # Same out-of-gap craft, but with a slot data CRC matching the bytes
        # actually stored in the out-of-gap range. On vulnerable code the load
        # then SUCCEEDS (exit 0) and returns device data from outside the
        # metadata area; on fixed code the header is rejected before any
        # read (exit 72).
        CRAFT_OFFSET=8192
        CRAFT_LENGTH=$((GAP_SIZE - 4096))
        rlRun "dd if=${LUKS_DEVICE} of=oog-data bs=1 skip=$((HOLE_OFFSET + CRAFT_OFFSET)) count=${CRAFT_LENGTH}" 0 \
            "Extract the bytes of the out-of-gap range"
        OOG_CRC=$(python3 ${TESTDIR}/patch_header.py crc oog-data)
        rlRun "python3 ${TESTDIR}/patch_header.py patch ${LUKS_DEVICE} 2 ${CRAFT_OFFSET} ${CRAFT_LENGTH} ${PAYLOAD_OFFSET} ${OOG_CRC}" 0 \
            "Craft slot 2 with data CRC matching the out-of-gap bytes"

        rlRun -s "luksmeta load -d ${LUKS_DEVICE} -s 2 -u ${CRAFT_UUID}" 72 \
            "Load from crafted slot 2 (must be rejected as corrupt)"
        rlAssertGrep "appears corrupt" "${rlRun_LOG}"
        rlRun "rm -f \$rlRun_LOG" 0

        rlRun "cryptsetup open ${LUKS_DEVICE} ${DEVNAME} <<< ${LUKS_PW}" 0 "Open LUKS device"
        rlRun "mount /dev/mapper/${DEVNAME} ${MOUNTPOINT}" 0 "Mounting the device for verification"
        rlRun "test \$(cat ${MOUNTPOINT}/luks1-test) = redhat" 0 "Verify encrypted payload not corrupted after load"
        rlRun "umount ${MOUNTPOINT}" 0 "Umounting the device"
        rlRun "cryptsetup close ${DEVNAME}" 0 "Closing the LUKS device"
    rlPhaseEnd

    rlPhaseStartTest "Wrapping slot endpoint is rejected"
        rlRun "luksmeta init -f -d ${LUKS_DEVICE}" 0 "Re-initialize luksmeta"

        # Craft slot 3 near UINT32_MAX so the 32-bit sum offset+length wraps
        # in luksmeta_wipe() (computed in 32-bit unsigned arithmetic),
        # mispositioning both the zeroing and the subsequent header rewrite
        # far past the end of the 512MB image. On vulnerable code the wipe
        # "succeeds" (exit 0) and grows the image by ~4GB; on fixed code the
        # range check (computed in uint64_t) rejects the header (exit 72).
        CRAFT_OFFSET=$((0xFFFFFF00))
        rlRun "python3 ${TESTDIR}/patch_header.py patch ${LUKS_DEVICE} 3 ${CRAFT_OFFSET} 512 ${PAYLOAD_OFFSET}" 0 \
            "Craft slot 3 with wrapping endpoint"

        SIZE_BEFORE=$(stat -c %s ${LUKS_DEVICE})
        rlRun -s "luksmeta wipe -d ${LUKS_DEVICE} -s 3 -u ${CRAFT_UUID} -f" 72 \
            "Wipe crafted slot 3 (must be rejected as corrupt)"
        rlAssertGrep "appears corrupt" "${rlRun_LOG}"
        rlRun "rm -f \$rlRun_LOG" 0
        SIZE_AFTER=$(stat -c %s ${LUKS_DEVICE})
        rlRun "test ${SIZE_BEFORE} = ${SIZE_AFTER}" 0 \
            "Verify image size unchanged (no mispositioned writes past EOF)"

        rlRun "cryptsetup open ${LUKS_DEVICE} ${DEVNAME} <<< ${LUKS_PW}" 0 "Open LUKS device"
        rlRun "mount /dev/mapper/${DEVNAME} ${MOUNTPOINT}" 0 "Mounting the device for verification"
        rlRun "test \$(cat ${MOUNTPOINT}/luks1-test) = redhat" 0 "Verify encrypted payload not corrupted"
        rlRun "umount ${MOUNTPOINT}" 0 "Umounting the device"
        rlRun "cryptsetup close ${DEVNAME}" 0 "Closing the LUKS device"
    rlPhaseEnd

    rlPhaseStartCleanup
        rlRun "umount ${MOUNTPOINT} ||:" 0 "Umounting the device, if mounted"
        rlRun "cryptsetup close ${DEVNAME} ||:" 0 "Closing the LUKS device, if opened"
        rlRun "popd"
        rlRun "rm -r \${tmp}" 0 "Remove tmp directory"
    rlPhaseEnd
rlJournalEnd
