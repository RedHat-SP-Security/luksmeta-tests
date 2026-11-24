#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   test.sh of /Security/large-metadata
#   Description: Test storing LARGE metadata to LUKS1 device
#   Author: Sergio Correia <scorreia@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2025 Red Hat, Inc. All rights reserved.
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

# PACKAGES is used by rlAssertRpm --all.
PACKAGES="luksmeta cryptsetup util-linux xfsprogs"
LUKS_PW=luks
DEVNAME="luks-${RANDOM}"

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
    rlPhaseEnd

    rlPhaseStartTest "Storing LARGE amount of metadata with luksmeta"
        rlRun "luksmeta init -f -d ${LUKS_DEVICE}" 0 "Initialize device with luksmeta"
        rlRun "dd if=/dev/urandom of=1M-file bs=1M count=1" 0 "Create 1MB file for the test"
        rlRun -s "luksmeta save -d ${LUKS_DEVICE} -s 1 -u 70e213ff-61fb-4dae-847e-d67b593f230b < 1M-file" 73 "Store large metadata to device"
        rlAssertGrep "Insufficient space in the LUKS header" "${rlRun_LOG}"
        rlRun "rm -f \$rlRun_LOG" 0
        rlRun "cryptsetup open ${LUKS_DEVICE} ${DEVNAME} <<< ${LUKS_PW}" 0 "Open LUKS device for verification"
        rlRun "mount /dev/mapper/${DEVNAME} /mnt" 0 "Mounting the device for verification"
        rlRun "test $(cat /mnt/luks1-test) = redhat" 0 "Check the test file is there with the right contents"
        rlRun "umount /mnt" 0 "Umounting the device"
        rlRun "cryptsetup close ${DEVNAME}" 0 "Closing the LUKS device"
    rlPhaseEnd

    rlPhaseStartTest "Gap boundary with slot 0 occupied"
        # init -f alone is a no-op on a valid header (luksmeta_init returns
        # -EALREADY, which cmd_init maps to exit 0), so nuke first to make
        # the reset real and the phase self-contained.
        rlRun "luksmeta init -f -n -d ${LUKS_DEVICE}" 0 "Nuke and re-initialize device with luksmeta"
        rlRun "dd if=/dev/urandom of=slot0-data bs=4096 count=1" 0 "Create 4KB file for slot 0"
        rlRun "luksmeta save -d ${LUKS_DEVICE} -s 0 -u cb6e8904-81e2-4c7e-9a1a-0c8c2d2b2e4f < slot0-data" 0 "Pre-populate slot 0 with metadata"
        # 24576 B = exact gap capacity (LUKS1, key-size 512, 4000 AF stripes -> 28672 B gap).
        # Sizes in (20480, 24576] exercise the shifted-boundary bug: pre-fix code accepts
        # the save and writes past the gap into the payload; fixed code rejects it.
        rlRun "dd if=/dev/urandom of=24k-file bs=4096 count=6" 0 "Create 24KB file (exact gap capacity) for the test"
        rlRun -s "luksmeta save -d ${LUKS_DEVICE} -s 1 -u 70e213ff-61fb-4dae-847e-d67b593f230b < 24k-file" 73 "Store capacity-sized metadata to slot 1 with slot 0 occupied"
        rlAssertGrep "Insufficient space in the LUKS header" "${rlRun_LOG}"
        rlRun "rm -f \$rlRun_LOG" 0
        rlRun "luksmeta load -d ${LUKS_DEVICE} -s 0 -u cb6e8904-81e2-4c7e-9a1a-0c8c2d2b2e4f > slot0-verify" 0 "Load slot 0 metadata back"
        rlRun "diff slot0-data slot0-verify" 0 "Verify slot 0 metadata is intact"
        rlRun "cryptsetup open ${LUKS_DEVICE} ${DEVNAME} <<< ${LUKS_PW}" 0 "Open LUKS device for verification"
        rlRun "mount /dev/mapper/${DEVNAME} /mnt" 0 "Mounting the device for verification"
        rlRun "test $(cat /mnt/luks1-test) = redhat" 0 "Check the encrypted payload is not corrupted"
        rlRun "umount /mnt" 0 "Umounting the device"
        rlRun "cryptsetup close ${DEVNAME}" 0 "Closing the LUKS device"
    rlPhaseEnd

    rlPhaseStartTest "Overlap check with large existing entry"
        # Nuke is required here: without it the gap-boundary phase's slot 0
        # entry survives the no-op init, and the allocator placement below
        # silently depends on it (on a vulnerable build the 24KB save from
        # the previous phase also leaves slot 1 occupied, so the 16KB save
        # fails with exit 69 instead of exercising the overlap path).
        rlRun "luksmeta init -f -n -d ${LUKS_DEVICE}" 0 "Nuke and re-initialize device with luksmeta"
        rlRun "dd if=/dev/urandom of=large-entry bs=4096 count=4" 0 "Create 16KB file (larger than 2 pages/8192 bytes)"
        rlRun "luksmeta save -d ${LUKS_DEVICE} -s 1 -u 70e213ff-61fb-4dae-847e-d67b593f230b < large-entry" 0 "Save 16KB entry to slot 1"
        rlRun "dd if=/dev/urandom of=small-entry bs=512 count=1" 0 "Create 512B file for overlap attempt"
        rlRun -s "luksmeta save -d ${LUKS_DEVICE} -s 2 -u ab4a6a22-15e5-4f92-b3c2-d7c5e3a81f9e < small-entry" 0 "Save small entry to slot 2 (must succeed, placed after the existing entry)"
        rlRun "rm -f \$rlRun_LOG" 0
        rlRun "luksmeta load -d ${LUKS_DEVICE} -s 1 -u 70e213ff-61fb-4dae-847e-d67b593f230b > large-verify" 0 "Load original large entry back"
        rlRun "diff large-entry large-verify" 0 "Verify the large entry in slot 1 is not corrupted"
        rlRun "cryptsetup open ${LUKS_DEVICE} ${DEVNAME} <<< ${LUKS_PW}" 0 "Open LUKS device for verification"
        rlRun "mount /dev/mapper/${DEVNAME} /mnt" 0 "Mounting the device for verification"
        rlRun "test $(cat /mnt/luks1-test) = redhat" 0 "Check the encrypted payload is not corrupted"
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
