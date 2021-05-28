"""
Module defines a Lastline Process Snapshot.

:Copyright:
    Copyright 2020 Lastline, Inc.  All Rights Reserved.
"""
import shutil
import logging
from collections import namedtuple


logger = logging.getLogger(__name__)


class Error(Exception):
    """Base-class for all exceptions in this module."""


class InvalidProcessSnapshot(Error):
    """Invalid Lastline Process Snapshot file."""


class UnsupportedVersionProcessSnapshot(Error):
    """Unsupported version of Lastline Process Snapshot file."""


LibraryExport = namedtuple("LibraryExport", ["name", "virtual_address"])

LoadedLibrary = namedtuple(
    "LoadedLibrary", ["name", "virtual_address", "exports", "size"]
)

PeImage = namedtuple(
    "PeImage",
    [
        "name",
        "virtual_address",
        "entry_point",
        "size",
        "sections",
        "object_uuid",
        "data",
    ],
)

PeSectionBase = namedtuple(
    "PeSectionBase",
    [
        "name",
        "virtual_address",
        "entry_points",
        "size",
        "characteristics",
        "object_uuid",
        "data",
    ],
)


class PeSection(PeSectionBase):
    """Represents PE section in snapshot."""

    # pe section cheracteristics
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000  # Section contains extended relocations.
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000  # Section can be discarded.
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000  # Section is not cachable.
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000  # Section is not pageable.
    IMAGE_SCN_MEM_SHARED = 0x10000000  # Section is shareable.
    IMAGE_SCN_MEM_EXECUTE = 0x20000000  # Section is executable.
    IMAGE_SCN_MEM_READ = 0x40000000  # Section is readable.
    IMAGE_SCN_MEM_WRITE = 0x80000000  # Section is writeable.

    def __init__(
        self,
        name,
        virtual_address,
        entry_points,
        size,
        characteristics,
        object_uuid,
        data,
    ):
        """
        PeSection object represents a PE Section in process address space.

        :param str name: PE section name
        :param int virtual_address: section virtual address
        :param list entry_points: list of entry points to the section detected during dynamic analysis
        :param int size: PE section size
        :param int characteristics: PE section characteristics
        :param str object_uuid: unique id of the PE section
        :param list data: PE section content
        """
        super(PeSectionBase, self).__init__(
            name,
            virtual_address,
            entry_points,
            size,
            characteristics,
            object_uuid,
            data,
        )

        self._is_read = characteristics & self.IMAGE_SCN_MEM_READ != 0
        self._is_write = characteristics & self.IMAGE_SCN_MEM_WRITE != 0
        self._is_execute = characteristics & self.IMAGE_SCN_MEM_EXECUTE != 0

    @property
    def is_read(self):
        return self._is_read

    @property
    def is_write(self):
        return self._is_write

    @property
    def is_execute(self):
        return self._is_execute


MemoryBlockBase = namedtuple(
    "MemoryBlockBase",
    [
        "name",
        "virtual_address",
        "entry_points",
        "size",
        "access",
        "object_uuid",
        "data",
    ],
)


class MemoryBlock(MemoryBlockBase):
    """Represents Virtual Memory block in snapshot."""

    # memory block access
    PAGE_NOACCESS = 0x01  # winnt
    PAGE_READONLY = 0x02  # winnt
    PAGE_READWRITE = 0x04  # winnt
    PAGE_WRITECOPY = 0x08  # winnt
    PAGE_EXECUTE = 0x10  # winnt
    PAGE_EXECUTE_READ = 0x20  # winnt
    PAGE_EXECUTE_READWRITE = 0x40  # winnt
    PAGE_EXECUTE_WRITECOPY = 0x80  # winnt
    PAGE_GUARD = 0x100  # winnt
    PAGE_NOCACHE = 0x200  # winnt
    PAGE_WRITECOMBINE = 0x400  # winnt

    def __init__(
        self, name, virtual_address, entry_points, size, access, object_uuid, data
    ):
        """
        MemoryBlock object represents a memory region in process address space.

        :param str name: name of the memory block as assigned by sandbox
        :param int virtual_address: virtual address of the memory block start address
        :param list entry_points: a list of entry points detected during dynamic analysis
        :param int size: a size of memory block
        :param int access: page protection for the memory block
        :param str object_uuid: unique id of the memory block
        :param list data: memory block content
        """
        super(MemoryBlockBase, self).__init__(
            name, virtual_address, entry_points, size, access, object_uuid, data
        )

        self._is_read = False
        if (
            (access & self.PAGE_READONLY)
            or (access & self.PAGE_READWRITE)
            or (access & self.PAGE_EXECUTE_READ)
            or (access & self.PAGE_EXECUTE_READWRITE)
        ):
            self._is_read = True

        self._is_write = False
        if (
            (access & self.PAGE_READWRITE)
            or (access & self.PAGE_WRITECOPY)
            or (access & self.PAGE_EXECUTE_READWRITE)
            or (access & self.PAGE_EXECUTE_WRITECOPY)
            or (access & self.PAGE_WRITECOMBINE)
        ):
            self._is_write = True

        self._is_execute = False
        if (
            (access & self.PAGE_EXECUTE)
            or (access & self.PAGE_EXECUTE_READ)
            or (access & self.PAGE_EXECUTE_READWRITE)
            or (access & self.PAGE_EXECUTE_WRITECOPY)
        ):
            self._is_execute = True

    @property
    def is_read(self):
        return self._is_read

    @property
    def is_write(self):
        return self._is_write

    @property
    def is_execute(self):
        return self._is_execute


class ProcessSnapshot(object):
    """Lastline Process Snapshot."""

    def __init__(
        self,
        storage_dir,
        version,
        snapshot_type,
        bitsize,
        snapshot_id,
        analysis_reason,
        loaded_libs,
        pe_images,
        memory_blocks,
    ):
        """
        Lastline Process Snapshot provides an access to memory
        layout extracted during dynamic analysis.

        :param storage_dir:
        :param version:
        :param snapshot_type:
        :param bitsize:
        :param snapshot_id:
        :param analysis_reason:
        :param loaded_lib:
        :param pe_images:
        :param memory_blocks:
        """
        self._storage_dir = storage_dir
        self._version = version
        self._type = snapshot_type
        self._bitsize = bitsize
        self._snapshot_id = snapshot_id
        self._analysis_reason = analysis_reason
        self._loaded_libs = loaded_libs
        self._pe_images = pe_images
        self._memory_blocks = memory_blocks

    @property
    def version(self):
        return self._version

    @property
    def type(self):
        return self._type

    @property
    def bitsize(self):
        return self._bitsize

    @property
    def snapshot_id(self):
        return self._snapshot_id

    @property
    def analysis_reason(self):
        return self._analysis_reason

    @property
    def loaded_libs(self):
        return self._loaded_libs

    @property
    def pe_images(self):
        return self._pe_images

    @property
    def memory_blocks(self):
        return self._memory_blocks

    def get_lib(self, va):
        """
        Get a loaded library associated with provides
            Virtual Address.

        :param int va: virtual address in memory space
        :return LoadedLibrary: loaded library associated with provides
            virtual address.
        """
        for lib in self._loaded_libs:
            if lib.virtual_address > va or lib.virtual_address + lib.size <= va:
                continue
            return lib


class ProcessSnapshotMgr(object):
    """
    Lastline Process Snapshot Manager provides an access to
    a collection of ProcessSnapshot extracted during dynamic analysis.
    """

    def __init__(self, snapshots, storage_dir):
        """

        :param dict snapshots: a dict of ProcessSnapshot objects
         a key is a tuple (snapshot_id, bitsize)
         a value is ProcessSnapshot
        :param storage_dir: a path to directory containing unpacked content of
            Lastline Process Snapshot file
        """
        self._snapshots = snapshots
        self._storage_dir = storage_dir

    def __del__(self):
        shutil.rmtree(self._storage_dir)

    @property
    def snapshots(self):
        return self._snapshots
