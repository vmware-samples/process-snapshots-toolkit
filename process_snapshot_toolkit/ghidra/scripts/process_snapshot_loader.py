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

def do_load_snapshot():
    decomp = m_decompiler.DecompInterface()
    decomp.openProgram(currentProgram)
    # m_decompiler.DecompInterface.setSimplificationStyle("normalize")
    options = m_decompiler.DecompileOptions()
    options.grabFromProgram(currentProgram)
    decomp.setOptions(options)

    snapshot_archive_filename = str(
        askFile(
            "Select a process snapshot archive file to load",  # Window Title
            "Select",  # approve button text
        )
    )
    logging.info("Loading snapshot archive %s", snapshot_archive_filename)
    snapshot_manager = factory.ProcessSnapshotMgrFactory.from_file(snapshot_archive_filename)
    choices = {
        "Snapshot {} ({}-bit)".format(k[0], k[1]): k for k in snapshot_manager.snapshots.keys()
    }
    choice_keys = sorted(choices.keys())
    snapshot_choice = askChoice(
        "Load Snapshot",  # Window Title
        "Snapshot",  # message by selection dropdown
        choice_keys,
        choice_keys[0],
    )
    snapshot = snapshot_manager.snapshots[choices[snapshot_choice]]
    if askYesNo(
        "Warning", (
            "Loading this snapshot will overwrite data stored in this code browser session. "
            "If you want to leave the data stored in this session unaltered, you may want to open "
            "a new code browser session with a copy of the file that you are analyzing."
        )
    ):
        postprocessing.load_snapshot(decomp, snapshot)

if __name__ == "__main__":
    do_load_snapshot()
