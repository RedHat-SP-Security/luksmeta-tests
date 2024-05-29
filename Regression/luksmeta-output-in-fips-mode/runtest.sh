#!/bin/bash
# vim: dict+=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/luksmeta/Regression/luksmeta-output-in-fips-mode
#   Description: Check if luksmeta doesn't print any output to STDOUT while FIPS is enabled
#   Author: Martin Zeleny <mzeleny@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2020 Red Hat, Inc.
#
#   This program is free software: you can redistribute it and/or
#   modify it under the terms of the GNU General Public License as
#   published by the Free Software Foundation, either version 2 of
#   the License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE.  See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program. If not, see http://www.gnu.org/licenses/.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include Beaker environment
. /usr/bin/rhts-environment.sh || exit 1
. /usr/share/beakerlib/beakerlib.sh || exit 1

PACKAGE="luksmeta"
PACKAGES="${PACKAGE} cryptsetup"

rlJournalStart
    rlPhaseStartSetup
        rlAssertRpm --all
        rlRun "TmpDir=\$(mktemp -d)" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"

        rlRun "dd if=/dev/zero of=luks1file bs=100M count=1" 0 "Create loopfile for luks1 encryption."
        rlRun "dd if=/dev/zero of=luks2file bs=100M count=1" 0 "Create loopfile for luks2 encryption."

        rlRun "luks1dev=\$(losetup -f --show luks1file)" 0 "Create luks1 device from loopfile"
        rlRun "luks2dev=\$(losetup -f --show luks2file)" 0 "Create luks2 device from loopfile"

        rlRun "echo -n redhat123 | cryptsetup luksFormat --batch-mode --key-file - ${luks1dev} --type luks1"
        rlRun "echo -n redhat123 | cryptsetup luksFormat --batch-mode --key-file - ${luks2dev}"
    rlPhaseEnd


    for dev in ${luks1dev} ${luks2dev}; do
        rlPhaseStartTest "Try to display LUKS metadata on ${dev}"
            rlRun -slt "luksmeta show -d ${dev} -s 1" "1-100" "Check if there is no luksmeta data in slot 1"
            rlAssertNotGrep "fips" $rlRun_LOG -i
            rlAssertNotGrep "STDOUT" $rlRun_LOG
            rm $rlRun_LOG
        rlPhaseEnd
    done


    rlPhaseStartCleanup
        rlRun "losetup -d ${luks1dev}"
        rlRun "losetup -d ${luks2dev}"
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
rlJournalPrintText
rlJournalEnd
