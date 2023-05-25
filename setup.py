"""
Copyright 2020-2021 VMware, Inc.
SPDX-License-Identifier: BSD-2-Clause

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
   provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

"""
Installation script for process-snapshot-toolkit
"""
import setuptools

setuptools.setup(
    name="process-snapshot-toolkit",
    version="0.1.0",
    description="VMware Toolkit to work with process snapshot.",
    url="https://github.com/Lastline-Inc/process-snapshot-toolkit",
    author="AMG at VMware, Inc.",
    license='BSD-2-Clause',
    packages=[
        "process_snapshot_toolkit",
        "process_snapshot_toolkit.ghidra",
        "process_snapshot_toolkit.snapshot",
        "process_snapshot_toolkit.snapshot.v3",
    ],
    scripts=[
        "scripts/ghidra_analyze.py",
    ],
    test_suite="nose.collector",
    install_requires=[
        "six",
    ],
    tests_require=[
        "mock",
        "nose",
        "nosexcover",
        "nose-timer",
        "tox",
    ],
    package_data={
        "process_snapshot_toolkit.ghidra": [
            "headless_scripts/*",
            "scripts/*",
        ]
    }
)

