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
Postprocessing script to decompile executable files
or/and Lastline Process Snapshot files using Ghidra.
"""

import argparse
import os
import sys
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# that is a super-hack to make Ghidra see our modules from post-processing script
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

from process_snapshot_toolkit.snapshot import factory
from process_snapshot_toolkit.ghidra import postprocessing

try:
    import ghidra.app.decompiler as m_decompiler
except ImportError as err:
    logger.error(
        "Ghidra postprocessing script cannot be run stand alone and needs to be run "
        "as part of Ghidra headless analysis. Error: %s",
        err,
    )


def do_postprocess(args):
    parser = argparse.ArgumentParser(
        usage="""
================================================================================
"""
        + __doc__.strip()
        + """
================================================================================

Postprocess script for Ghidra Decompiler

"""
    )
    parser.add_argument(
        "output_dir", default=None, help="Output directory to store results"
    )
    parser.add_argument(
        "snapshot_file",
        default=None,
        nargs="?",
        help="Lastline snapshot file to decompile and extract data from",
    )

    args = parser.parse_args(args)

    executable_name = os.path.basename(currentProgram.getExecutablePath())
    logger.info("Processing file: %s", executable_name)
    if args.snapshot_file:
        logger.info("Snapshot file: %s", args.snapshot_file)
    logger.info("Output directory: %s", args.output_dir)

    decompiled_functions = set()
    decomp = m_decompiler.DecompInterface()
    decomp.openProgram(currentProgram)
    # m_decompiler.DecompInterface.setSimplificationStyle("normalize")
    options = m_decompiler.DecompileOptions()
    options.grabFromProgram(currentProgram)
    decomp.setOptions(options)

    source_path = os.path.join(args.output_dir, "{}.c".format(executable_name))
    postprocessing.extract_decompiled_functions(decomp, source_path)

    postprocessing.extract_called_functions(
        os.path.join(args.output_dir, "{}.called".format(executable_name))
    )
    postprocessing.extract_pcode_functions(
        decomp, os.path.join(args.output_dir, "{}.pcode".format(executable_name))
    )

    if args.snapshot_file:
        snapshot_manager = factory.ProcessSnapshotMgrFactory.from_file(
            args.snapshot_file
        )
        for (snapshot_id, bitsize), snapshot in snapshot_manager.snapshots.items():
            logger.info("Processing snapshot id: %d bitsize: %d", snapshot_id, bitsize)
            if not postprocessing.load_snapshot(decomp, snapshot):
                continue
            dst_name = "{}_{}_{}".format(
                os.path.basename(args.snapshot_file), snapshot_id, bitsize
            )
            source_path = os.path.join(args.output_dir, "{}.c".format(dst_name))
            postprocessing.extract_decompiled_functions(decomp, source_path, snapshot)
            postprocessing.extract_called_functions(
                os.path.join(args.output_dir, "{}.called".format(dst_name)), snapshot
            )
            postprocessing.extract_pcode_functions(
                decomp,
                os.path.join(args.output_dir, "{}.pcode".format(dst_name)),
                snapshot,
            )


if __name__ == "__main__":
    do_postprocess(getScriptArgs())
