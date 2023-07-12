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
Module provides interfaces to Ghidra to decompile files.
"""

import logging
import os
import tempfile
import shutil
import subprocess

logger = logging.getLogger(__name__)


class Error(Exception):
    """Base-class for all exceptions in this module."""


class InvalidGhidraSettings(Error):
    """Invalid parameters for Ghidra Decompiler."""


class InvalidDecompilationTarget(Error):
    """Invalid target to decompile."""


class GhidraDecompiler(object):
    """Interface to Ghidra to decompile exe files and Lastline process snapshots."""

    def __init__(self, ghidra_dir, verbose=False):
        """
        Interface to launch Ghidra decompiler.

        :param str ghidra_dir: path to Ghidra directory
        :param str postprocessing_script_path: path to Ghidra postprocessing script
        """
        self._ghidra_dir = ghidra_dir
        self._postprocessing_script_path = os.path.join(
            os.path.dirname(__file__), "headless_scripts", "postprocess.py"
        )
        self._verbose = verbose

    @classmethod
    def from_args_and_conf(cls, args, conf):
        """
        Create GhidraDecompiler from args and conf objects.
        Read the Ghidra directory from the commandline or the config file and
        create GhidraDecompiler object.

        :param GhidraDecompiler cls: GhidraDecompiler class to create object of
        :param argparse.Namespace args: command line arguments
        :param ConfigParser.ConfigParser conf: configuration from config file
        :raise: file_decompiler.ghidra.decompiler.InvalidGhidraSettings
        :returns: Ghidra decompiler interface
        :rtype: file_decompiler.ghidra.decompiler.GhidraDecompiler
        """
        ghidra_dir = None
        if args and args.ghidra_dir:
            ghidra_dir = args.ghidra_dir
        elif conf and conf.has_option("ghidra", "ghidra_dir"):
            ghidra_dir = conf.get("ghidra", "ghidra_dir")

        if not ghidra_dir or not os.path.isdir(ghidra_dir):
            raise InvalidGhidraSettings(
                "Unable to find Ghidra directory: {}".format(ghidra_dir)
            )

        return cls(ghidra_dir, args.verbose)

    def decompile_snapshot_file(self, exe_file_path, snapshot_file_path, output_dir):
        """
        Decompile target of pair EXE file and Lastline Process snapshot.

        :param str exe_file_path: path to EXE file
        :param str snapshot_file_path: path to Lastline process snapshot
        :param str output_dir: Output directory to write decompiled code
        :return: list of generated files
        :rtype: list
        """
        if not os.path.isfile(exe_file_path):
            raise InvalidDecompilationTarget(
                "Unable to access exe file {}".format(exe_file_path)
            )

        if not os.path.isfile(snapshot_file_path):
            raise InvalidDecompilationTarget(
                "Unable to access snapshot file {}".format(snapshot_file_path)
            )

        if not os.path.isdir(output_dir):
            os.mkdir(output_dir)

        ghidra_work_dir = tempfile.mkdtemp()
        try:
            logger.info(
                "Decompiling pair (%s:%s) to %s",
                exe_file_path,
                snapshot_file_path,
                output_dir,
            )
            ghidra_cmd = [
                os.path.join(self._ghidra_dir, "support/analyzeHeadless"),
                ghidra_work_dir,
                "tmp_ghidra_project",
                "-deleteProject",
                "-import",
                exe_file_path,
                "-postscript",
                self._postprocessing_script_path,
                output_dir,
                snapshot_file_path,
            ]

            with open(os.devnull, "w") as f:
                kwargs = {}
                if not self._verbose:
                    kwargs['stdout'] = f
                    kwargs['stderr'] = f
                subprocess.check_call(ghidra_cmd, **kwargs)

        finally:
            shutil.rmtree(ghidra_work_dir)

    def decompile_exe_file(self, exe_file_path, output_dir):
        """
        Decompile Lastline Process snapshot.

        :param str exe_file_path: path to EXE file
        :param str output_dir: Output directory to write decompiled code
        :return: list of generated files
        :rtype: list
        """
        if not os.path.isfile(exe_file_path):
            raise InvalidDecompilationTarget(
                "Unable to access exe file {}".format(exe_file_path)
            )

        if not os.path.isdir(output_dir):
            os.mkdir(output_dir)

        ghidra_work_dir = tempfile.mkdtemp()
        try:
            logger.info("Decompiling EXE file %s to %s", exe_file_path, output_dir)
            ghidra_cmd = [
                os.path.join(self._ghidra_dir, "support/analyzeHeadless"),
                ghidra_work_dir,
                "tmp_ghidra_project",
                "-deleteProject",
                "-import",
                exe_file_path,
                "-postscript",
                self._postprocessing_script_path,
                output_dir,
            ]

            with open(os.devnull, "w") as f:
                kwargs = {}
                if not self._verbose:
                    kwargs['stdout'] = f
                    kwargs['stderr'] = f
                subprocess.check_call(ghidra_cmd, **kwargs)
        finally:
            shutil.rmtree(ghidra_work_dir)
