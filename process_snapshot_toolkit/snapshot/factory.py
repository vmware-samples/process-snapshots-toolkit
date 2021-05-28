"""
Define Lastline Process snapshot factory

:Copyright:
    Copyright 2020 Lastline, Inc.  All Rights Reserved.
"""

import logging
import os
import struct
from . import v3
from process_snapshot_toolkit import snapshot

logger = logging.getLogger(__name__)


class Error(Exception):
    """Base-class for all exceptions in this module."""


class ProcessSnapshotMgrFactory(object):
    """Lastline Process Snapshot Manager Factory."""

    SUPPORTED_SNAPSHOT_VERSIONS = {3: v3.ProcessSnapshotMgrV3}

    def __init__(self, snapshots, storage_dir):
        self._snapshots = snapshots
        self._storage_dir = storage_dir

    @staticmethod
    def get_version(snapshot_path):
        """
        Get version of binary Lastline process snapshot file
        :param str snapshot_path: Path to Lastline process snapshot
        :raise snapshot.InvalidProcessSnapshot: invalid format for process snapshot
        """
        if not os.path.isfile(snapshot_path):
            raise snapshot.InvalidProcessSnapshot(
                "Unable to parse Process Snapshot: {} doesn't exist".format(
                    snapshot_path
                )
            )

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
            return version

    @classmethod
    def from_file(cls, snapshot_path):
        """
        Create ProcessSnapshotMgr from file.

        :param snapshot_path: a path to snapshot file
        :return: ProcessSnapshotMgr object
        """
        version = cls.get_version(snapshot_path)
        if version not in cls.SUPPORTED_SNAPSHOT_VERSIONS:
            raise snapshot.UnsupportedVersionProcessSnapshot(
                "Unable to parse Process Snapshot: {} is an unsupported version".format(
                    version
                )
            )
        process_snapshot_mgr = cls.SUPPORTED_SNAPSHOT_VERSIONS[version]
        return process_snapshot_mgr.from_file(snapshot_path)
