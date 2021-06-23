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
This module contains the testcases for the process_snapshot_toolkit.ghidra module.
"""
try:
    import ConfigParser as configparser
except ImportError:
    import configparser
import mock
import unittest
from process_snapshot_toolkit.ghidra import decompiler as m_decompiler

MODULE = "process_snapshot_toolkit.ghidra.decompiler"


class MockArguments(object):
    """Mock arguments class"""

    def __init__(self, ghidra_dir, decompiler_script_path, verbose):
        self.ghidra_dir = ghidra_dir
        self.decompiler_script_path = decompiler_script_path
        self.verbose = verbose


class TestUtils(object):
    """Utility collection for test_ghidra."""

    @staticmethod
    def get_mock_config(ghidra_dir="", decompiler_script_path=""):
        config = configparser.RawConfigParser()
        ghidra_section_name = "ghidra"
        config.add_section(ghidra_section_name)
        config.set(ghidra_section_name, "ghidra_dir", ghidra_dir)
        config.set(
            ghidra_section_name, "decompiler_script_path", decompiler_script_path
        )
        return config

    @staticmethod
    def get_mock_args(ghidra_dir="", decompiler_script_path="", verbose=False):
        return MockArguments(ghidra_dir, decompiler_script_path, verbose)

    @staticmethod
    def get_mock_decompiler(ghidra_dir="", decompiler_script_path="", verbose=False):
        with mock.patch("{}.os.path.isfile".format(MODULE), clear=True) as mock_isfile:
            with mock.patch(
                "{}.os.path.isdir".format(MODULE), clear=True
            ) as mock_isdir:
                return m_decompiler.GhidraDecompiler.from_args_and_conf(
                    TestUtils.get_mock_args(
                        ghidra_dir, decompiler_script_path, verbose
                    ),
                    TestUtils.get_mock_config(ghidra_dir, decompiler_script_path),
                )


class TestGhidraDecompiler(unittest.TestCase):
    """Testcases for ghidra.decompiler."""

    GHIDRA_DIR = "ghidra_dir/path"
    GHIDRA_SCRIPT = "decompiler/postprocessing_script_path.py"

    def test_ghidra_from__incorrect_args_and_conf(self):
        with self.assertRaises(m_decompiler.InvalidGhidraSettings):
            m_decompiler.GhidraDecompiler.from_args_and_conf(
                TestUtils.get_mock_args(self.GHIDRA_DIR, self.GHIDRA_SCRIPT),
                TestUtils.get_mock_config(self.GHIDRA_DIR, self.GHIDRA_SCRIPT),
            )

        with self.assertRaises(m_decompiler.InvalidGhidraSettings):
            m_decompiler.GhidraDecompiler.from_args_and_conf(
                TestUtils.get_mock_args(),
                TestUtils.get_mock_config(self.GHIDRA_DIR, self.GHIDRA_SCRIPT),
            )

        with self.assertRaises(m_decompiler.InvalidGhidraSettings):
            m_decompiler.GhidraDecompiler.from_args_and_conf(
                TestUtils.get_mock_args(self.GHIDRA_DIR, self.GHIDRA_SCRIPT),
                TestUtils.get_mock_config(),
            )

        with self.assertRaises(m_decompiler.InvalidGhidraSettings):
            m_decompiler.GhidraDecompiler.from_args_and_conf(
                TestUtils.get_mock_args(self.GHIDRA_DIR),
                TestUtils.get_mock_config(self.GHIDRA_DIR),
            )

        with self.assertRaises(m_decompiler.InvalidGhidraSettings):
            m_decompiler.GhidraDecompiler.from_args_and_conf(
                TestUtils.get_mock_args("", self.GHIDRA_SCRIPT),
                TestUtils.get_mock_config("", self.GHIDRA_SCRIPT),
            )

        with self.assertRaises(m_decompiler.InvalidGhidraSettings):
            m_decompiler.GhidraDecompiler.from_args_and_conf(
                TestUtils.get_mock_args(), TestUtils.get_mock_config()
            )

    @mock.patch("{}.os.path.isfile".format(MODULE), clear=True)
    @mock.patch("{}.os.path.isdir".format(MODULE), clear=True)
    def test_ghidra_from__no_script_found(self, mock_isfile, mock_isdir):
        with self.assertRaises(m_decompiler.InvalidGhidraSettings):
            m_decompiler.GhidraDecompiler.from_args_and_conf(
                TestUtils.get_mock_args(self.GHIDRA_DIR),
                TestUtils.get_mock_config(self.GHIDRA_DIR),
            )

    @mock.patch("{}.os.path.isfile".format(MODULE), clear=True)
    @mock.patch("{}.os.path.isdir".format(MODULE), clear=True)
    def test_ghidra_from__correct_args(self, mock_isfile, mock_isdir):

        m_decompiler.GhidraDecompiler.from_args_and_conf(
            TestUtils.get_mock_args(self.GHIDRA_DIR, self.GHIDRA_SCRIPT),
            TestUtils.get_mock_config(self.GHIDRA_DIR, self.GHIDRA_SCRIPT),
        )

        m_decompiler.GhidraDecompiler.from_args_and_conf(
            TestUtils.get_mock_args(),
            TestUtils.get_mock_config(self.GHIDRA_DIR, self.GHIDRA_SCRIPT),
        )

        m_decompiler.GhidraDecompiler.from_args_and_conf(
            TestUtils.get_mock_args(self.GHIDRA_DIR, self.GHIDRA_SCRIPT),
            TestUtils.get_mock_config(),
        )

    @mock.patch("{}.os.path.isfile".format(MODULE), clear=True)
    @mock.patch("{}.os.path.isdir".format(MODULE), clear=True)
    @mock.patch("{}.tempfile.mkdtemp".format(MODULE), clear=True)
    @mock.patch("{}.subprocess.Popen".format(MODULE), clear=True)
    @mock.patch("{}.subprocess.Popen.communicate".format(MODULE), clear=True)
    @mock.patch("{}.shutil.rmtree".format(MODULE), clear=True)
    def test_ghidra_decompile_snapshot_file(
        self,
        mock_isfile,
        mock_isdir,
        mock_tempfile,
        mock_popen,
        mock_popen_communicate,
        mock_rmtree,
    ):
        EXE_PATH = "exe_file"
        SNAPSHOT_PATH = "process_snapshot"
        OUTPUT_DIR = "output/directory/"
        decompiler = m_decompiler.GhidraDecompiler.from_args_and_conf(
            TestUtils.get_mock_args(self.GHIDRA_DIR, self.GHIDRA_SCRIPT),
            TestUtils.get_mock_config(self.GHIDRA_DIR, self.GHIDRA_SCRIPT),
        )
        decompiler.decompile_snapshot_file(EXE_PATH, SNAPSHOT_PATH, OUTPUT_DIR)

    @mock.patch("{}.os.path.isfile".format(MODULE), clear=True)
    @mock.patch("{}.os.path.isdir".format(MODULE), clear=True)
    @mock.patch("{}.tempfile.mkdtemp".format(MODULE), clear=True)
    @mock.patch("{}.subprocess.Popen".format(MODULE), clear=True)
    @mock.patch("{}.subprocess.Popen.communicate".format(MODULE), clear=True)
    @mock.patch("{}.shutil.rmtree".format(MODULE), clear=True)
    def test_ghidra_decompile_exe_file(
        self,
        mock_isfile,
        mock_isdir,
        mock_tempfile,
        mock_popen,
        mock_popen_communicate,
        mock_rmtree,
    ):
        EXE_PATH = "exe_file"
        OUTPUT_DIR = "output/directory/"
        decompiler = m_decompiler.GhidraDecompiler.from_args_and_conf(
            TestUtils.get_mock_args(self.GHIDRA_DIR, self.GHIDRA_SCRIPT),
            TestUtils.get_mock_config(self.GHIDRA_DIR, self.GHIDRA_SCRIPT),
        )
        decompiler.decompile_exe_file(EXE_PATH, OUTPUT_DIR)

    @mock.patch("{}.tempfile.mkdtemp".format(MODULE), clear=True)
    @mock.patch("{}.subprocess.Popen".format(MODULE), clear=True)
    @mock.patch("{}.subprocess.Popen.communicate".format(MODULE), clear=True)
    @mock.patch("{}.shutil.rmtree".format(MODULE), clear=True)
    def test_ghidra_fail_decompile_snapshot_file(
        self, mock_tempfile, mock_popen, mock_popen_communicate, mock_rmtree
    ):
        EXE_PATH = "exe_file"
        SNAPSHOT_PATH = "process_snapshot"
        OUTPUT_DIR = "output/directory/"

        decompiler = TestUtils.get_mock_decompiler(
            self.GHIDRA_DIR, self.GHIDRA_SCRIPT, True
        )
        with self.assertRaises(m_decompiler.InvalidDecompilationTarget):
            decompiler.decompile_snapshot_file(EXE_PATH, SNAPSHOT_PATH, OUTPUT_DIR)

        with mock.patch("{}.os.path.isfile".format(MODULE), clear=True) as mock_isfile:
            with mock.patch("{}.os.mkdir".format(MODULE), clear=True) as mock_mkdir:
                decompiler.decompile_snapshot_file(EXE_PATH, SNAPSHOT_PATH, OUTPUT_DIR)

    @mock.patch("{}.tempfile.mkdtemp".format(MODULE), clear=True)
    @mock.patch("{}.subprocess.Popen".format(MODULE), clear=True)
    @mock.patch("{}.subprocess.Popen.communicate".format(MODULE), clear=True)
    @mock.patch("{}.shutil.rmtree".format(MODULE), clear=True)
    def test_ghidra_fail_decompile_exe_file(
        self, mock_tempfile, mock_popen, mock_popen_communicate, mock_rmtree
    ):
        EXE_PATH = "exe_file"
        OUTPUT_DIR = "output/directory/"

        decompiler = TestUtils.get_mock_decompiler(
            self.GHIDRA_DIR, self.GHIDRA_SCRIPT, True
        )
        with self.assertRaises(m_decompiler.InvalidDecompilationTarget):
            decompiler.decompile_exe_file(EXE_PATH, OUTPUT_DIR)

        with mock.patch("{}.os.path.isfile".format(MODULE), clear=True) as mock_isfile:
            with mock.patch("{}.os.mkdir".format(MODULE), clear=True) as mock_mkdir:
                decompiler.decompile_exe_file(EXE_PATH, OUTPUT_DIR)


if __name__ == "__main__":
    unittest.main()
