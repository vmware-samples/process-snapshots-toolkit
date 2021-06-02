#!/usr/bin/python
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
Run Ghidra with a postprocessing script to decompile exe and VMware Anti-Malware Sandbox Process snapshot files.
"""

import argparse
import logging
import six.moves.configparser  # pylint: disable=import-error

from process_snapshot_toolkit.ghidra import decompiler as ghidra_decompiler


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Error(Exception):
    """Base-class for all exceptions in this module."""


class IncorrectDecompileTarget(Error):
    """Incorrect target for decompilation provided."""


class MethodNotImplemented(Error):
    """Method is not implemented yet."""


def process_target_dirs(decompiler, target_dirs):
    """
    Process multiple directory based targets.

    The target directory structure:
        <target_dir>
            <target_exe_file>
            <metadata_dir>/process_snapshot_2 // snapshot file

    :param binary_feature_extractor.ghidra.decompiler.\
        GhidraDecompiler decompiler: Ghidra decompiler object
    :param list<str> target_dirs: list of target directories
    :return:
    """
    _ = decompiler
    _ = target_dirs
    raise MethodNotImplemented("Method process_target_dirs is not implemented yet")


def validate_params(args):
    """
    Validates input arguments.

    :param argparse.Namespace args: input arguments from conf file and command line
    :raise: IncorrectDecompileTarget
    :return: None
    """

    if not args.exe_file and not args.target_list:
        raise IncorrectDecompileTarget(
            "Neither EXE file nor a list of directories provided!"
        )

    if args.exe_file and args.target_list:
        raise IncorrectDecompileTarget("Cannot process targets. Too many target types!")

    if args.target_list and args.output_dir:
        raise IncorrectDecompileTarget(
            "Output directory cannot be set for multiple targets!"
        )


def do_main():
    parser = argparse.ArgumentParser(
        usage="""
================================================================================
"""
        + __doc__.strip()
        + """
================================================================================

Analyze executable file or Lastline Process Snapshot using Ghidra decompiler.

"""
    )
    parser.add_argument(
        "-c", "--config", metavar="FILE", help="Read configuration options from FILE"
    )
    parser.add_argument(
        "--exe-file",
        dest="exe_file",
        default=None,
        help="Path to executable file to decompile and extract data from",
    )
    parser.add_argument(
        "--snapshot-file",
        dest="snapshot_file",
        default=None,
        help="Path to Lastline snapshot file to decompile and extract data from",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        dest="output_dir",
        default=None,
        help="Directory to store output results",
    )
    parser.add_argument(
        "--ghidra-dir",
        dest="ghidra_dir",
        default=None,
        help="Directory with Ghidra repo",
    )
    parser.add_argument(
        "--decompiler-script-path",
        dest="decompiler_script_path",
        default=None,
        help="Path to Ghidra postprocessing script",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        default=False,
        help="Print verbose output of decompilation",
    )
    parser.add_argument(
        "target_list",
        default=list(""),
        nargs="*",
        help="List of directories with input data.",
    )

    args = parser.parse_args()
    if args.config:
        conf = six.moves.configparser.ConfigParser()
        conf.read(args.config)
    else:
        conf = None

    validate_params(args)

    decompiler = ghidra_decompiler.GhidraDecompiler.from_args_and_conf(args, conf)

    if args.exe_file and args.snapshot_file:
        decompiler.decompile_snapshot_file(
            args.exe_file, args.snapshot_file, args.output_dir
        )
    elif args.exe_file:
        decompiler.decompile_exe_file(args.exe_file, args.output_dir)
    elif args.target_list:
        process_target_dirs(decompiler, args.target_list)


if __name__ == "__main__":
    """Main function of the script."""
    do_main()
