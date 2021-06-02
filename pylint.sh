#!/bin/bash
# Copyright 2020-2021 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
#    provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

PACKAGE_NAME="process_snapshot_toolkit"

# Pylint options (format, in particular) are different in precise and trusty
. /etc/os-release
if [[ $PRETTY_NAME == *"precise"* ]]; then
    PYLINT_FMT=('--output-format=parseable' '--include-ids=yes')
else
    PYLINT_FMT=("--msg-template='{path}:{line}: [{msg_id}({symbol}), {obj}] {msg}'")
fi

# W0511 are alerts for warning notes in comments: we disable it here instead of
# putting it in the config file with the other suppressions so that one can run
# pylint --rcfile=.pylintrc and see those alerts.
pylint "${PYLINT_FMT[@]}" \
        --rcfile=./.pylintrc --disable=W0511 \
        ${PACKAGE_NAME} ${PACKAGE_NAME}_test \
        scripts/*
