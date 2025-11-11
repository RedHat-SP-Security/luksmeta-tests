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
    rlPhaseEnd

    rlPhaseStartCleanup
        rlRun "umount /mnt ||:" 0 "Umounting the device, if mounted"
        rlRun "cryptsetup close ${DEVNAME} ||:" 0 "Closing the LUKS device, if opened"
        rlRun "popd"
        rlRun "rm -r \${tmp}" 0 "Remove tmp directory"
    rlPhaseEnd
rlJournalEnd
