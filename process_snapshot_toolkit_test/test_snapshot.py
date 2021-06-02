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
This module contains the testcases for the process_snapshot_toolkit.snapshot modules.
"""

import os
import mock
import unittest
from process_snapshot_toolkit import snapshot as m_snapshot
from process_snapshot_toolkit.snapshot import factory as m_factory
from process_snapshot_toolkit.snapshot import utils as m_utils

MODULE = "process_snapshot_toolkit.snapshot"

CORRUPT_SNAPSHOT_1 = {
    "analysis_reason": "analyze_module_execution",
    "bitsize": 32,
}

CORRUPT_SNAPSHOT_2 = 5

CORRUPT_SNAPSHOT_MEMORY_BLOCK_1 = {
    "analysis_reason": "analyze_module_execution",
    "bitsize": 32,
    "version": 3,
    "snapshot_id": 0,
    "type": "LLAMA_SNAPSHOT_DUMP_INFO",
    "memory_blocks": [
        {
            "object_description": "vm_memory_block",
            "virtual_address": "0x74b20000",
        }
    ],
}

CORRUPT_SNAPSHOT_MEMORY_BLOCK_2 = {
    "analysis_reason": "analyze_module_execution",
    "bitsize": 32,
    "version": 3,
    "snapshot_id": 0,
    "type": "LLAMA_SNAPSHOT_DUMP_INFO",
    "memory_blocks": [
        {
            "object_uuid": "mem_535dd6e78b02a39f33e612c5ea1376c5",
            "virtual_address": "0x74b20000",
        }
    ],
}

CORRUPT_SNAPSHOT_PE_IMAGE_1 = {
    "analysis_reason": "analyze_module_execution",
    "bitsize": 32,
    "version": 3,
    "snapshot_id": 0,
    "type": "LLAMA_SNAPSHOT_DUMP_INFO",
    "pe_images": [
        {
            "entry_point": "0x3334",
            "loaded": True,
            "object_description": "setup-stub.exe",
            "virtual_address": "0x400000",
        }
    ],
}

CORRUPT_SNAPSHOT_PE_IMAGE_2 = {
    "analysis_reason": "analyze_module_execution",
    "bitsize": 32,
    "version": 3,
    "snapshot_id": 0,
    "type": "LLAMA_SNAPSHOT_DUMP_INFO",
    "pe_images": [
        {
            "entry_point": "0x3334",
            "loaded": True,
            "object_uuid": "pe_535dd6e78b02a39f33e612c5ea1376c5",
            "virtual_address": "0x400000",
        }
    ],
}

CORRUPT_SNAPSHOT_LOADED_LIB_1 = {
    "analysis_reason": "analyze_module_execution",
    "bitsize": 32,
    "version": 3,
    "snapshot_id": 0,
    "type": "LLAMA_SNAPSHOT_DUMP_INFO",
    "loaded_libraries": [
        {
            "virtual_address": "0x699b0000",
        }
    ],
}
CORRUPT_SNAPSHOT_LOADED_LIB_2 = {
    "analysis_reason": "analyze_module_execution",
    "bitsize": 32,
    "version": 3,
    "snapshot_id": 0,
    "type": "LLAMA_SNAPSHOT_DUMP_INFO",
    "loaded_libraries": [
        {
            "object_description": "oleacc.dll",
        }
    ],
}

CORRECT_SNAPSHOT_V3 = {
    "analysis_reason": "analyze_module_execution",
    "bitsize": 32,
    "loaded_libraries": [
        {
            "exports": {
                "0x7456321e": {"name": "LoadIconMetric", "ordinal": 378, "rva": 12830},
                "0x74563e12": {"name": "ImageList_ReadEx", "ordinal": 75, "rva": 15890},
            },
            "object_description": "oleacc.dll",
            "virtual_address": "0x699b0000",
        },
    ],
    "memory_blocks": [
        {
            "entry_points_rva": [
                {
                    "description": "Code execution in untrusted memory region",
                    "rva": "0x1000",
                },
                {
                    "description": "Code execution in untrusted memory region",
                    "rva": "0x1401",
                },
            ],
            "object_data": {
                "access": "0x20",
                "executed_pages": ["0x74b20000", "0x74b21000"],
                "trusted": False,
            },
            "object_description": "vm_memory_block",
            "object_uuid": "mem_a2292f8d63d5e4f73065f83def42093a",
            "virtual_address": "0x74b20000",
        }
    ],
    "pe_images": [
        {
            "entry_point": "0x3334",
            "loaded": True,
            "object_description": "setup-stub.exe",
            "object_uuid": "pe_535dd6e78b02a39f33e612c5ea1376c5",
            "sections": [
                {
                    "characteristics": "0x60000020",
                    "entry_points_rva": [
                        {
                            "description": "Code execution in .text section",
                            "rva": "0x335d",
                        }
                    ],
                    "name": ".text",
                    "object_uuid": "section_7debcff221b3a7497c692cae1041e3d3",
                    "virtual_address": "0x401000",
                },
                {
                    "characteristics": "0x40000040",
                    "name": ".rdata",
                    "object_uuid": "section_1193e0ab33ffbad899ede543d0fc46bc",
                    "virtual_address": "0x408000",
                },
                {
                    "characteristics": "0xc0000040",
                    "name": ".data",
                    "object_uuid": "section_5fbb86237b959086862f12edc26a35a9",
                    "virtual_address": "0x40a000",
                },
                {
                    "characteristics": "0x40000040",
                    "name": ".rsrc ",
                    "object_uuid": "section_80e63ed34dbe6bb34184228dd479d00e",
                    "virtual_address": "0x467000",
                },
            ],
            "virtual_address": "0x400000",
        }
    ],
    "snapshot_id": 0,
    "type": "LLAMA_SNAPSHOT_DUMP_INFO",
    "version": 3,
}


class TestSnapshotManager(unittest.TestCase):
    """Testcases for snapshot.*."""

    DATA_DIR = "process_snapshot_toolkit_test/test_data/snapshot"
    SNAPSHOT_32BIT_NAME = "process_snapshots_1"
    SNAPSHOT_64BIT_NAME = "chrome.process_snapshots_1"
    SNAPSHOT_PACKED_NAME = "dump.process_snapshots_1"
    TRUNC_SNAPSHOT_NAME = "process_snapshots_1_trunc"
    WRONG_VERSION_SNAPSHOT_NAME = "process_snapshots_1_wrong_version"
    NOT_EXIST_SNAPSHOT_PATH = "this/snapshot/doesnt/exist"

    def _check_library_export(self, library, export_name, virtual_address):
        self.assertTrue(virtual_address in library.exports)
        self.assertEqual(library.exports[virtual_address].name, export_name)
        self.assertEqual(
            library.exports[virtual_address].virtual_address, virtual_address
        )

    def _check_loaded_library(
        self, loaded_library, name, virtual_address, size, num_exports
    ):
        self.assertEqual(loaded_library.name, name)
        self.assertEqual(loaded_library.virtual_address, virtual_address)
        self.assertEqual(loaded_library.size, size)
        self.assertEqual(len(loaded_library.exports), num_exports)

    def _check_pe_image(
        self,
        pe_image,
        name,
        object_uuid,
        virtual_address,
        size,
        entry_point,
        num_sections,
    ):
        self.assertEqual(pe_image.name, name)
        self.assertEqual(pe_image.object_uuid, object_uuid)
        self.assertEqual(pe_image.entry_point, entry_point)
        self.assertEqual(pe_image.virtual_address, virtual_address)
        self.assertEqual(pe_image.size, size)
        self.assertEqual(len(pe_image.sections), num_sections)

    def _check_pe_section(
        self,
        pe_section,
        name,
        object_uuid,
        entry_points,
        virtual_address,
        size,
        is_read,
        is_write,
        is_execute,
    ):
        self.assertEqual(pe_section.name, name)
        self.assertEqual(pe_section.object_uuid, object_uuid)
        for ep in entry_points:
            self.assertTrue(ep in pe_section.entry_points)
        self.assertEqual(len(pe_section.entry_points), len(entry_points))
        self.assertEqual(pe_section.virtual_address, virtual_address)
        self.assertEqual(pe_section.size, size)
        self.assertEqual(pe_section.is_read, is_read)
        self.assertEqual(pe_section.is_write, is_write)
        self.assertEqual(pe_section.is_execute, is_execute)

    def _check_memory_block(
        self,
        memory_block,
        name,
        object_uuid,
        entry_points,
        virtual_address,
        size,
        is_read,
        is_write,
        is_execute,
    ):
        self.assertEqual(memory_block.name, name)
        self.assertEqual(memory_block.object_uuid, object_uuid)
        if entry_points:
            for ep in entry_points:
                self.assertTrue(ep in memory_block.entry_points)
            self.assertEqual(len(memory_block.entry_points), len(entry_points))
        self.assertEqual(memory_block.virtual_address, virtual_address)
        self.assertEqual(memory_block.size, size)
        self.assertEqual(memory_block.is_read, is_read)
        self.assertEqual(memory_block.is_write, is_write)
        self.assertEqual(memory_block.is_execute, is_execute)

    def _check_snapshot(
        self,
        snapshot,
        version,
        bitsize,
        snapshot_id,
        analysis_reason,
        num_loaded_libs,
        num_pe_images,
        num_memory_blocks,
    ):
        self.assertEqual(snapshot.version, version)
        self.assertEqual(snapshot.type, "LLAMA_SNAPSHOT_DUMP_INFO")
        self.assertEqual(snapshot.bitsize, bitsize)
        self.assertEqual(snapshot.snapshot_id, snapshot_id)
        self.assertEqual(snapshot.analysis_reason, analysis_reason)
        self.assertEqual(len(snapshot.loaded_libs), num_loaded_libs)
        self.assertEqual(len(snapshot.pe_images), num_pe_images)
        self.assertEqual(len(snapshot.memory_blocks), num_memory_blocks)

    def test_snapshot_factory_on_packed_snapshot(self):
        """Test the ProcessSnapshotMgrFactory class using 32 bit snapshot"""
        snapshot_path = os.path.join(self.DATA_DIR, self.SNAPSHOT_PACKED_NAME)

        version = m_factory.ProcessSnapshotMgrFactory.get_version(snapshot_path)
        snapshot_manager = m_factory.ProcessSnapshotMgrFactory.from_file(snapshot_path)

        self.assertEqual(version, 3)
        self.assertEqual(len(snapshot_manager.snapshots), 5)

        self._check_snapshot(
            snapshot_manager.snapshots[(0, 32)],
            3,
            32,
            0,
            "analyze_module_execution",
            19,
            1,
            0,
        )
        self._check_snapshot(
            snapshot_manager.snapshots[(1, 32)],
            3,
            32,
            1,
            "call_from_untrusted_memory: NtCreateFile",
            35,
            1,
            2,
        )
        snapshot_1_32 = snapshot_manager.snapshots[(1, 32)]

        self._check_memory_block(
            snapshot_1_32.memory_blocks[0],
            "vm_memory_block",
            "mem_aa746d15ab670f2107ade5686b212eb7",
            None,
            0x687B1000,
            0x1000,
            True,
            False,
            True,
        )
        self._check_memory_block(
            snapshot_1_32.memory_blocks[1],
            "vm_memory_block",
            "mem_a2292f8d63d5e4f73065f83def42093a",
            None,
            0x74B20000,
            0x1000,
            True,
            False,
            True,
        )

    def test_snapshot_factory_on_32bit_snapshot(self):
        """Test the ProcessSnapshotMgrFactory class using 32 bit snapshot"""
        snapshot_path = os.path.join(self.DATA_DIR, self.SNAPSHOT_32BIT_NAME)

        version = m_factory.ProcessSnapshotMgrFactory.get_version(snapshot_path)
        snapshot_manager = m_factory.ProcessSnapshotMgrFactory.from_file(snapshot_path)

        self.assertEqual(version, 3)
        self.assertEqual(len(snapshot_manager.snapshots), 2)

        self._check_snapshot(
            snapshot_manager.snapshots[(0, 32)],
            3,
            32,
            0,
            "analyze_module_execution",
            3,
            1,
            0,
        )
        self._check_snapshot(
            snapshot_manager.snapshots[(1, 32)],
            3,
            32,
            1,
            "process_termination",
            3,
            1,
            0,
        )

        snapshot_0_32 = snapshot_manager.snapshots[(0, 32)]
        self._check_loaded_library(
            snapshot_0_32.loaded_libs[0], "KERNELBASE.DLL", 0x755A0000, 0x41000, 625
        )

        self._check_library_export(
            snapshot_0_32.loaded_libs[0], "GetFileSize", 0x755ADFEA
        )
        kernelbase_lib = snapshot_0_32.get_lib(0x755ADFEA)
        self.assertEqual(snapshot_0_32.loaded_libs[0], kernelbase_lib)

        self._check_pe_image(
            snapshot_0_32.pe_images[0],
            "calc.exe",
            "pe_29074e853ef3597649331aa867cb7329",
            0x400000,
            0x15000,
            0x127C,
            4,
        )
        pe_image = snapshot_0_32.pe_images[0]

        self._check_pe_section(
            pe_image.sections[0],
            ".text",
            "section_fcf8149d140ab59c2d331977cc6a7d06",
            [0x2BB5, 0x53AD],
            0x401000,
            0xC000,
            True,
            False,
            True,
        )
        self._check_pe_section(
            pe_image.sections[1],
            ".rdata",
            "section_5079e0a6fa5881a5984801a2dce8aa72",
            [],
            0x40D000,
            0x5000,
            True,
            False,
            False,
        )
        self._check_pe_section(
            pe_image.sections[2],
            ".data",
            "section_5d622283c5de502e5f862878da12a350",
            [],
            0x412000,
            0x2000,
            True,
            True,
            False,
        )
        self._check_pe_section(
            pe_image.sections[3],
            ".rsrc ",
            "section_c87aad0b685d523773d68ff113ca9031",
            [],
            0x415000,
            0x1000,
            True,
            False,
            False,
        )

    def test_snapshot_factory_on_64bit_snapshot(self):
        """Test the ProcessSnapshotMgrFactory class using 64 bit snapshot"""
        snapshot_path = os.path.join(self.DATA_DIR, self.SNAPSHOT_64BIT_NAME)

        version = m_factory.ProcessSnapshotMgrFactory.get_version(snapshot_path)
        snapshot_manager = m_factory.ProcessSnapshotMgrFactory.from_file(snapshot_path)

        self.assertEqual(version, 3)

        self.assertEqual(len(snapshot_manager.snapshots), 3)
        self._check_snapshot(
            snapshot_manager.snapshots[(0, 64)],
            3,
            64,
            0,
            "analyze_module_execution",
            41,
            1,
            0,
        )
        self._check_snapshot(
            snapshot_manager.snapshots[(1, 64)],
            3,
            64,
            1,
            "call_from_untrusted_memory: NtCreateFile",
            42,
            1,
            0,
        )
        self._check_snapshot(
            snapshot_manager.snapshots[(2, 64)],
            3,
            64,
            2,
            "call_from_untrusted_memory: NtCreateProcess",
            43,
            1,
            0,
        )

        snapshot_0_64 = snapshot_manager.snapshots[(0, 64)]

        self._check_pe_image(
            snapshot_0_64.pe_images[0],
            "69ee4dfc31e8dcfa4dda4f041a107e0c8d221b427ff98.exe",
            "pe_c258fecac829ca3c65ace3fcaf9485c6",
            0x13FCF0000,
            0x265000,
            0x18FFF0,
            11,
        )
        pe_image = snapshot_0_64.pe_images[0]

        self._check_pe_section(
            pe_image.sections[0],
            ".text",
            "section_ecf58216c524777566c1c2ea7e34d8bd",
            [0xBB4F0],
            0x13FCF1000,
            0x1BA000,
            True,
            False,
            True,
        )
        self._check_pe_section(
            pe_image.sections[1],
            ".rdata",
            "section_c8675c83ebc04de37e7e254346235195",
            [],
            0x13FEAB000,
            0x42000,
            True,
            False,
            False,
        )
        self._check_pe_section(
            pe_image.sections[2],
            ".data",
            "section_7b2b86d5340e16f7f527a0d389779b8b",
            [],
            0x13FEED000,
            0x3000,
            True,
            True,
            False,
        )
        self._check_pe_section(
            pe_image.sections[3],
            ".pdata",
            "section_9b12fa433f411bd1b47d38e92cf34fa5",
            [],
            0x13FEF9000,
            0xF000,
            True,
            False,
            False,
        )

    def test_snapshot_factory_on_truncated_snapshot(self):
        """Test the ProcessSnapshotMgrFactory class using truncated snapshot"""
        snapshot_path = os.path.join(self.DATA_DIR, self.TRUNC_SNAPSHOT_NAME)
        version = m_factory.ProcessSnapshotMgrFactory.get_version(snapshot_path)
        self.assertEqual(version, 3)

        with self.assertRaises(m_snapshot.InvalidProcessSnapshot):
            m_factory.ProcessSnapshotMgrFactory.from_file(snapshot_path)

    def test_snapshot_factory_on_wrong_version(self):
        """Test the ProcessSnapshotMgrFactory class using snapshot with wrong version"""
        snapshot_path = os.path.join(self.DATA_DIR, self.WRONG_VERSION_SNAPSHOT_NAME)

        version = m_factory.ProcessSnapshotMgrFactory.get_version(snapshot_path)
        self.assertEqual(version, 0xFF)

        with self.assertRaises(m_snapshot.UnsupportedVersionProcessSnapshot):
            m_factory.ProcessSnapshotMgrFactory.from_file(snapshot_path)

    def test_snapshot_factory_on_incorrect_path(self):
        """Test the ProcessSnapshotMgrFactory class using snapshot with wrong version"""
        with self.assertRaises(m_snapshot.InvalidProcessSnapshot):
            m_factory.ProcessSnapshotMgrFactory.get_version(
                self.NOT_EXIST_SNAPSHOT_PATH
            )
        with self.assertRaises(m_snapshot.InvalidProcessSnapshot):
            m_factory.ProcessSnapshotMgrFactory.from_file(self.NOT_EXIST_SNAPSHOT_PATH)

    def test_utils_va_from_string(self):
        """Test the m_snapshot.utils.va_from_string method."""

        self.assertEqual(m_utils.va_from_string("fdsafdsf"), 0)
        self.assertEqual(m_utils.va_from_string("000"), 0)
        self.assertEqual(m_utils.va_from_string("0001"), 1)
        self.assertEqual(m_utils.va_from_string("0001L"), 1)
        self.assertEqual(
            m_utils.va_from_string("FF00FF00FF00FF00L"), 0xFF00FF00FF00FF00
        )
        self.assertEqual(
            m_utils.va_from_string("0xFF00FF00FF00FF00L"), 0xFF00FF00FF00FF00
        )

    @mock.patch(
        "{}.os.path.isfile".format("process_snapshot_toolkit.snapshot.v3"), clear=True
    )
    @mock.patch(
        "{}.os.path.isdir".format("process_snapshot_toolkit.snapshot.v3"), clear=True
    )
    @mock.patch(
        "{}.os.path.getsize".format("process_snapshot_toolkit.snapshot.v3"), clear=True
    )
    @mock.patch("{}.open".format("process_snapshot_toolkit.snapshot.v3"), clear=True)
    def test_snapshot_v3(self, mock_isfile, mock_isdir, mock_getsize, mock_open):
        storage_dir = "test/path/to/dir"
        m_snapshot.v3.ProcessSnapshotV3.from_dict(CORRECT_SNAPSHOT_V3, storage_dir)

    @mock.patch(
        "{}.os.path.isfile".format("process_snapshot_toolkit.snapshot.v3"), clear=True
    )
    @mock.patch(
        "{}.os.path.isdir".format("process_snapshot_toolkit.snapshot.v3"), clear=True
    )
    @mock.patch(
        "{}.os.path.getsize".format("process_snapshot_toolkit.snapshot.v3"), clear=True
    )
    @mock.patch("{}.open".format("process_snapshot_toolkit.snapshot.v3"), clear=True)
    def test_corrupt_snapshot(self, mock_isfile, mock_isdir, mock_getsize, mock_open):
        storage_dir = "test/path/to/dir"
        m_snapshot.v3.ProcessSnapshotV3.from_dict(CORRUPT_SNAPSHOT_1, storage_dir)
        m_snapshot.v3.ProcessSnapshotV3.from_dict(CORRUPT_SNAPSHOT_2, storage_dir)
        m_snapshot.v3.ProcessSnapshotV3.from_dict(
            CORRUPT_SNAPSHOT_PE_IMAGE_1, storage_dir
        )
        m_snapshot.v3.ProcessSnapshotV3.from_dict(
            CORRUPT_SNAPSHOT_PE_IMAGE_2, storage_dir
        )
        m_snapshot.v3.ProcessSnapshotV3.from_dict(
            CORRUPT_SNAPSHOT_MEMORY_BLOCK_1, storage_dir
        )
        m_snapshot.v3.ProcessSnapshotV3.from_dict(
            CORRUPT_SNAPSHOT_MEMORY_BLOCK_2, storage_dir
        )
        m_snapshot.v3.ProcessSnapshotV3.from_dict(
            CORRUPT_SNAPSHOT_LOADED_LIB_1, storage_dir
        )
        m_snapshot.v3.ProcessSnapshotV3.from_dict(
            CORRUPT_SNAPSHOT_LOADED_LIB_1, storage_dir
        )


if __name__ == "__main__":
    unittest.main()
