"""
Module describes Lastline Process snapshot version 3.

:Copyright:
    Copyright 2020 Lastline, Inc.  All Rights Reserved.
"""

import struct
import tempfile
import json
import os
import logging

from os import path
from os import walk

from process_snapshot_toolkit import snapshot
from process_snapshot_toolkit.snapshot import utils


logger = logging.getLogger(__name__)


class Error(Exception):
    """Base-class for all exceptions in this module."""


class ProcessSnapshotV3(snapshot.ProcessSnapshot):
    """
    Lastline Process Snapshots V3.
    It provides an access to memory layout extracted during dynamic analysis.
    """

    @classmethod
    def from_dict(cls, snapshot_dict, storage_dir):
        """
        Create ProcessSnapshotV3 from dictionary.

        :param dict snapshot_dict: snapshot object as dict
        :param str storage_dir: path to a directory with unpacked
            Lastline Process Snapshot file content
        :return:
        """
        try:
            loaded_lib = list()
            if "loaded_libraries" in snapshot_dict:
                loaded_lib = ProcessSnapshotV3._parse_loaded_libraries(
                    snapshot_dict["loaded_libraries"]
                )

            pe_images = list()
            if "pe_images" in snapshot_dict:
                pe_images = ProcessSnapshotV3._parse_pe_images(
                    snapshot_dict["pe_images"], storage_dir
                )

            memory_blocks = list()
            if "memory_blocks" in snapshot_dict:
                memory_blocks = ProcessSnapshotV3._parse_memory_blocks(
                    snapshot_dict["memory_blocks"], storage_dir
                )
            return cls(
                storage_dir,
                snapshot_dict["version"],
                snapshot_dict["type"],
                snapshot_dict["bitsize"],
                snapshot_dict["snapshot_id"],
                snapshot_dict["analysis_reason"],
                loaded_lib,
                pe_images,
                memory_blocks,
            )

        except (TypeError, KeyError) as err:
            logger.error("Incorrectly formatted snapshot. Error: %s", err)
            return None

    @staticmethod
    def _parse_pe_images(pe_images_node, storage_dir):
        """
        Parse PeImage list from dictionary.

        :param dict pe_images_node: dict node with the list of PE Images
        :param storage_dir: path to directory with unpacked Lastline Process Snapshot
        file content
        :return list: list of parsed PeImage
        """
        pe_images = list()
        for pe in pe_images_node:
            try:
                pe_image_name = pe["object_uuid"]
            except KeyError as err:
                logger.error("Failed to parse PE Image. Error: %s", err)
                continue

            try:
                if not pe["loaded"]:
                    continue
                pe_sections = list()
                if "sections" in pe:
                    for section in pe["sections"]:
                        pe_section_path = os.path.join(
                            storage_dir, section["object_uuid"]
                        )
                        section_size = os.path.getsize(pe_section_path)
                        entry_points = list()
                        if "entry_points_rva" in section:
                            for ep in section["entry_points_rva"]:
                                entry_points.append(utils.va_from_string(ep["rva"]))
                        with open(pe_section_path, "rb") as data_file:
                            pe_section_data = data_file.read()

                        pe_sections.append(
                            snapshot.PeSection(
                                str(section["name"]),
                                utils.va_from_string(section["virtual_address"]),
                                entry_points,
                                section_size,
                                utils.va_from_string(section["characteristics"]),
                                str(section["object_uuid"]),
                                pe_section_data,
                            )
                        )

                pe_file_path = os.path.join(storage_dir, pe_image_name)
                pe_size = os.path.getsize(pe_file_path)
                with open(pe_file_path, "rb") as data_file:
                    pe_data = data_file.read()

                pe_images.append(
                    snapshot.PeImage(
                        pe["object_description"],
                        utils.va_from_string(pe["virtual_address"]),
                        utils.va_from_string(pe["entry_point"]),
                        pe_size,
                        pe_sections,
                        pe["object_uuid"],
                        pe_data,
                    )
                )
            except (TypeError, KeyError) as err:
                logger.error(
                    "Failed to parse PE Image: %s. Error: %s", pe_image_name, err
                )
                continue

        return pe_images

    @staticmethod
    def _parse_memory_blocks(memory_blocks_node, storage_dir):
        """
        Parse Memory Block list from dictionary.

        :param dict memory_blocks_node: dict node with the list of Memory Blocks
        :param storage_dir: path to directory with unpacked Lastline Process Snapshot
        file content
        :return list: list of parsed MemoryBlock
        """
        memory_blocks = list()
        for block in memory_blocks_node:
            try:
                memory_block_uuid = block["object_uuid"]
            except KeyError as err:
                logger.error("Failed to parse  Memory Block. Error: %s", err)
                continue

            try:
                entry_points = list()
                if "entry_points_rva" in block:
                    for ep in block["entry_points_rva"]:
                        entry_points.append(utils.va_from_string(ep["rva"]))

                memory_block_path = os.path.join(storage_dir, memory_block_uuid)
                memory_block_size = os.path.getsize(memory_block_path)
                memory_block_access = utils.va_from_string(
                    block["object_data"]["access"]
                )
                with open(memory_block_path, "rb") as data_file:
                    memory_block_data = data_file.read()

                memory_blocks.append(
                    snapshot.MemoryBlock(
                        str(block["object_description"]),
                        utils.va_from_string(block["virtual_address"]),
                        entry_points,
                        memory_block_size,
                        memory_block_access,
                        str(block["object_uuid"]),
                        memory_block_data,
                    )
                )
            except (TypeError, KeyError) as err:
                logger.error(
                    "Failed to parse Memory Block: %s. Error: %s",
                    memory_block_uuid,
                    err,
                )
                continue

        return memory_blocks

    @staticmethod
    def _parse_loaded_libraries(loaded_lib_node):
        """
        Parse Loaded Libraries list from dictionary.

        :param dict loaded_lib_node: dict node with the list of Loaded Libraries
        :param storage_dir: path to directory with unpacked Lastline Process Snapshot
        file content
        :return list: list of parsed LoadedLibrary
        """
        loaded_libs = list()
        for lib in loaded_lib_node:
            try:
                lib_name = str(lib["object_description"]).upper()
            except KeyError as err:
                logger.error("Failed to parse Loaded Library. Error: %s", err)
                continue

            try:
                lib_va = utils.va_from_string(lib["virtual_address"])
                lib_exports = dict()
                lib_max_rva = 0x1000
                if "exports" in lib:
                    for export in lib["exports"].itervalues():
                        export_va = lib_va + export["rva"]
                        lib_exports[export_va] = snapshot.LibraryExport(
                            str(export["name"]), export_va
                        )
                        if export["rva"] > lib_max_rva:
                            lib_max_rva = export["rva"] + 1
                lib_max_rva = (lib_max_rva & ~0xFFF) + 0x1000
                loaded_libs.append(
                    snapshot.LoadedLibrary(lib_name, lib_va, lib_exports, lib_max_rva)
                )

            except (TypeError, KeyError) as err:
                logger.error(
                    "Failed to parse Loaded Library: %s. Error: %s", lib_name, err
                )
                continue

        return loaded_libs


class ProcessSnapshotMgrV3(snapshot.ProcessSnapshotMgr):
    """
    Manager of Lastline Process Snapshots V3.
    It provides an access to a collection of ProcessSnapshotV3
    extracted during dynamic analysis.
    """

    PROCESS_DUMP_VERSION = 3
    CODEHASH_VERSION = 4

    @staticmethod
    def get_snapshot_buffer(snapshot_path):
        """
        Verifies a file format and returns a buffer which contains
        tar.gz payload of the Lastline Process Snapshot.

        :param str snapshot_path: Path to Lastline process snapshot
        :raise snapshot.InvalidProcessSnapshot: invalid format for process snapshot
        :returns: buffer containing tar.gz payload of the snapshot
        """
        statinfo = os.stat(snapshot_path)
        with open(snapshot_path, "rb") as snapshot_file:
            file_size = statinfo.st_size

            snapshot_file.seek(0, 2)
            snapshot_file.seek(0)

            buf = snapshot_file.read(file_size)
            if buf is None:
                raise snapshot.InvalidProcessSnapshot(
                    "Unable to parse Process Snapshot: incorrect file size"
                )
            if buf.startswith(b"LASTLINE PROCESS DUMP INFO"):
                buf = buf[0x20:]
            else:
                raise snapshot.InvalidProcessSnapshot(
                    "Unable to parse Process Snapshot: incorrect magic header"
                )

            version = struct.unpack("<I", buf[0:4])[0]
            if version != ProcessSnapshotMgrV3.PROCESS_DUMP_VERSION:
                raise snapshot.InvalidProcessSnapshot(
                    "Unable to parse Process Snapshot: incorrect version {}".format(
                        version
                    )
                )

            size = struct.unpack("<I", buf[4:8])[0]
            if size > len(buf) - 8:
                raise snapshot.InvalidProcessSnapshot(
                    "Unable to parse Process Snapshot: incorrect size {}".format(size)
                )
            buf = buf[8 : size + 8]
            return buf

    @classmethod
    def from_file(cls, snapshot_path):
        """
        Creates ProcessSnapshotMgrV3 from the file.

        :param str snapshot_path: Path to Lastline process snapshot
        :raise snapshot.InvalidProcessSnapshot: invalid format for process snapshot
        :returns ProcessSnapshotMgrV3: ProcessSnapshotMgrV3 object
        """
        buf = cls.get_snapshot_buffer(snapshot_path)

        tmp_dir = tempfile.mkdtemp()
        file_path_tar = path.join(tmp_dir, "process_snapshot.tar")
        file_path_tar_gz = file_path_tar + ".gz"
        with open(file_path_tar_gz, "wb") as f_gz:
            f_gz.write(buf)

        utils.extract_gz_archive(file_path_tar_gz, file_path_tar)
        utils.extract_tar_archive(file_path_tar, tmp_dir)

        snapshots = {}
        for (dirpath, _, filenames) in walk(tmp_dir):
            for name in filenames:
                if name.startswith("snapshot") and name.endswith(".json"):
                    with open(path.join(dirpath, name)) as snapshot_json_file:
                        snapshot_data = json.load(snapshot_json_file)
                        snapshots[
                            (snapshot_data["snapshot_id"], snapshot_data["bitsize"])
                        ] = ProcessSnapshotV3.from_dict(snapshot_data, dirpath)
            break

        return cls(snapshots, tmp_dir)
