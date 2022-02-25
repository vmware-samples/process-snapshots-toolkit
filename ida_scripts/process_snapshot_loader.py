"""
This module allows importing NSX Advanced Threat Analyzer snapshots into IDA Pro.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

:Copyright:
     Copyright 2021 VMware, Inc.  All Rights Reserved.
"""
__author__ = 'VMware, Inc.'
__version__ = '1.3.0'

import argparse
import itertools
import os
import tempfile
import sys

from process_snapshot_toolkit import snapshot
from process_snapshot_toolkit.snapshot import utils
from process_snapshot_toolkit.snapshot import factory

# Imports that are not available when tested
try:
    import ida_auto
    import ida_bytes
    import ida_entry
    import ida_idp
    import ida_kernwin
    import ida_lines
    import ida_nalt
    import ida_name
    import ida_netnode
    import ida_segment
    import ida_xref
    import idautils
    import idc
except ImportError:
    import mock
    ida_auto = mock.Mock()
    ida_bytes = mock.Mock()
    ida_entry = mock.Mock()
    ida_idp = mock.Mock()
    ida_kernwin = mock.Mock()
    ida_lines = mock.Mock()
    ida_nalt = mock.Mock()
    ida_name = mock.Mock()
    ida_netnode = mock.Mock()
    ida_segment = mock.Mock()
    ida_xref = mock.Mock()
    idautils = mock.Mock()
    idc = mock.Mock()

# Whether to allow loading 32bit snapshots in IDA64
ALLOW_32_ON_64 = True

# Constants
IDA_BITSIZE_32 = 32
IDA_BITSIZE_64 = 64


class ApiReferences:
    """Class resolving cross-references (poorly tested and documented)."""

    XREF_JMP = frozenset([
        ida_xref.fl_JF,                         # define fl_JF   18  // Code Jump Far
        ida_xref.fl_JN,                         # define fl_JN   19  // Code Jump Near
    ])

    XREF_CALL = frozenset([
        ida_xref.fl_CF,                         # define fl_CF   16  // Code Call Far
        ida_xref.fl_CN,                         # define fl_CN   17  // Code Call Near
    ])

    XREF_ALL = frozenset({
        ida_xref.dr_O,                          # define dr_O    1   // Data offset
    }.union(XREF_CALL, XREF_JMP))

    @classmethod
    def check_prev_reference(cls, address, delta):
        """
        Recursively accumulate set of variable addresses.

        :param int address: the variable address
        :param int delta: the known delta
        :rtype: set[int]
        :return: previous references
        """

        def __check_prev_reference(va, delta, va_set, level, max_level=1):
            """
            Recursively accumulate set of variable addresses.

            :param int va: the variable address
            :param int delta: the delta
            :param set[int] va_set: accumulating set
            :param int level: current recursive depth
            :param int max_level: the maximum recursive depth
            :rtype: int
            :return: number of cross-references
            """
            if level >= max_level:
                return 0

            level += 1
            xrefs_count = 0

            # Get all the cross-references pointing to this address VA
            for xref in idautils.XrefsTo(va, 0):
                if xref.type not in cls.XREF_ALL:
                    continue

                xrefs_count += 1

                # ADD THE PREVIOUS ONE IF THE PREVIOUS ONE IS USED AT ALL
                # If the cross-reference is a data offset reference
                if xref.type == ida_xref.dr_O:
                    # ADD the source of the cross-reference IFF the source is a destination as well
                    for _ in idautils.XrefsTo(xref.frm, 0):  # generator
                        va_set.add(xref.frm)
                        __check_prev_reference(xref.frm, 0, va_set, level)
                        break

                # Otherwise if it is a CALL or JMP, check the DREFs
                else:
                    # ADD all the chain of cross-references until and including the FROM of this cross-reference
                    current_dref = ida_xref.get_first_dref_from(xref.frm)
                    while current_dref != 0xffffffff and current_dref != 0xffffffffffffffff:
                        va_set.add(current_dref)
                        current_dref = ida_xref.get_next_dref_from(xref.frm, current_dref)

                # But if we had no luck when looking at the FROM
                if not __check_prev_reference(xref.frm, delta, va_set, level):
                    # And the cross-reference is a JMP and there is a delta defined
                    if xref.type in cls.XREF_JMP and delta:
                        # Let us try again with the delta, and add the FROM as well
                        if __check_prev_reference(xref.frm - delta, 0, va_set, level):
                            va_set.add(xref.frm - delta)
            return xrefs_count

        refs_va = set([])
        __check_prev_reference(address, delta, refs_va, level=0, max_level=1)
        return refs_va

    @classmethod
    def make_func_name(cls, va, name, flags=None):
        """
        Rename an address and pad it as much as possible with underscores.

        :param int va: the virtual address
        :param str name: the name
        :param int flags: combination of flags
        """
        if not flags:
            flags = (ida_name.SN_NOCHECK | ida_name.SN_NOWARN)
        cur_name = name
        while not idc.set_name(va, cur_name, flags):
            cur_name += "_"
            if len(cur_name) > 50:
                break

    @staticmethod
    def get_segment_xrefs(va):
        """
        Get all cross-refs to a segment.

        :params int va_string: the virtual address of the segment
        :rtype: set
        :return: set of cross references
        """
        # get all cross-references pointing to the segment
        cross_refs = set([])
        for ea in idautils.Heads(idc.get_segm_start(va), idc.get_segm_end(va)):
            for _ in idautils.XrefsTo(ea, 0):  # generator
                cross_refs.add(ea)
                break
        return cross_refs

    @classmethod
    def align_reference(cls, reference, exports):
        delta = 0
        while (reference - delta) not in exports and delta < 20:
            delta += 1
        return reference - delta, delta

    @classmethod
    def analyze_api_refs(cls, p_snapshot):
        """
        Analyze cross-references to external modules.

        :param ProcessSnapshot p_snapshot: the snapshot dump
        """
        for lib in p_snapshot.loaded_libs:

            # Get all references pointing TO the current library (dll)
            print("Searching XREFS for segment: {}".format(lib.virtual_address))
            for ref in cls.get_segment_xrefs(lib.virtual_address):
                fixed_ref, delta = cls.align_reference(ref, lib.exports)
                export = lib.exports.get(fixed_ref)
                if export:
                    print("\tFound cross-reference {} to {} (delta={})".format(ref, export.name, delta))
                    # Rename it
                    cls.make_func_name(ref, export.name)
                    # Get also all the cross-reference pointing to this cross-reference
                    for previous_ref in cls.check_prev_reference(ref, delta):
                        cls.make_func_name(previous_ref, export.name)
                        ida_entry.add_entry(previous_ref, previous_ref, export.name, 0)

            # Tag the Export Table as such (data)
            ida_bytes.create_data(lib.virtual_address, ida_bytes.FF_BYTE, 1, ida_netnode.BADNODE)
            for va, export in lib.exports.items():
                ida_bytes.create_data(va, ida_bytes.FF_BYTE, 1, ida_netnode.BADNODE)
                # And rename functions if they do not have a name already
                if not idc.get_name(va, ida_name.GN_VISIBLE):
                    name_flags = (ida_name.SN_NOCHECK | ida_name.SN_NOWARN | ida_name.SN_NOLIST)
                    cls.make_func_name(va, export.name, name_flags)
            idc.plan_and_wait(lib.virtual_address, lib.virtual_address + lib.size)


def add_segment(va_start, va_end, name, seg_type, seg_mode, data=None):
    """
    Add a segment (that in IDA speaking is a piece of code).

    :param int va_start: the start virtual address
    :param int va_end: the end virtual address
    :param str name: the segment name
    :param str seg_type: the segment type
    :param int seg_mode: the segment mode
    :param str|None data: if not None, it contains the file path to he actual data
    """
    print("\t{}-{} segment '{}' (type={}, mode={})".format(
        hex(va_start), hex(va_end), name, seg_type, seg_mode))
    ida_segment.add_segm(0, va_start, va_end, name, seg_type)
    ida_segment.set_segm_addressing(ida_segment.get_segm_by_name(name), 2)
    idc.set_default_sreg_value(va_start, "es", 0)
    idc.set_default_sreg_value(va_start, "ds", 0)
    idc.set_default_sreg_value(va_start, "cs", 0)
    if data:
        ida_bytes.put_bytes(va_start, data)


def load_snapshot(p_snapshot):
    """
    Load the snapshot.

    :param ProcessSnapshot p_snapshot: the snapshot info
    :raise ValueError: if loading the snapshot fails for some reason
    """
    if p_snapshot.bitsize == IDA_BITSIZE_32:
        seg_mode = 1
    elif p_snapshot.bitsize == IDA_BITSIZE_64:
        seg_mode = 2
    else:
        raise ValueError("Unknown bitsize {}".format(p_snapshot.bitsize))

    entry_point = None
    ida_idp.set_processor_type("p4", ida_idp.SETPROC_LOADER_NON_FATAL | ida_idp.SETPROC_LOADER)
    for lib in p_snapshot.loaded_libs:
        add_segment(
            va_start=lib.virtual_address,
            va_end=lib.virtual_address + lib.size,
            name=lib.name,
            seg_type="CODE",
            seg_mode=seg_mode,
            data=None,
        )
        idc.plan_and_wait(lib.virtual_address, lib.virtual_address + lib.size)

    for pe_image in p_snapshot.pe_images:
        if not pe_image.sections:
            add_segment(
                va_start=pe_image.virtual_address,
                va_end=pe_image.virtual_address + pe_image.size,
                name=pe_image.object_uuid,
                seg_type="UNK",
                seg_mode=seg_mode,
                data=pe_image.data,
            )
        else:
            for section in pe_image.sections:
                add_segment(
                    va_start=section.virtual_address,
                    va_end=section.virtual_address + section.size,
                    name="{}.{}".format(section.name.strip(), section.object_uuid),
                    seg_type="CODE" if section.is_execute else "DATA",
                    seg_mode=seg_mode,
                    data=section.data,
                )
                for entry_point in section.entry_points:
                    description = "entry_point.{}".format(section.object_uuid)
                    entry_point = section.virtual_address + entry_point
                    ida_entry.add_entry(entry_point, entry_point, description, 1)
                    ida_auto.auto_make_proc(entry_point)
        if pe_image.entry_point:
            description = "entry_point.{}".format(pe_image.object_uuid)
            entry_point = pe_image.virtual_address + pe_image.entry_point
            ida_entry.add_entry(entry_point, entry_point, description, 1)
            ida_auto.auto_make_proc(entry_point)
        idc.plan_and_wait(pe_image.virtual_address, pe_image.virtual_address + pe_image.size)

    for block in p_snapshot.memory_blocks:
        add_segment(
            va_start=block.virtual_address,
            va_end=block.virtual_address + block.size,
            name=block.object_uuid,
            seg_type="CODE" if block.is_execute else "DATA",
            seg_mode=seg_mode,
            data=block.data,
        )
        for entry_point in block.entry_points:
            description = "entry_point.{}".format(block.object_uuid)
            entry_point = block.virtual_address + entry_point
            ida_entry.add_entry(entry_point, entry_point, description, 1)
            ida_auto.auto_make_proc(entry_point)
        idc.plan_and_wait(block.virtual_address, block.virtual_address + block.size)

    print("Loading of the binary data complete! Analyze loaded libraries...")
    ApiReferences.analyze_api_refs(p_snapshot)
    if entry_point:
        ida_kernwin.jumpto(entry_point)


def create_line_color(start_va, end_va, color=0xfff2e0):
    """
    Add highlight lines to the selected range.

    :param int start_va: the start virtual address
    :param int end_va: the end virtual address
    :param int color: the color
    """
    while start_va <= end_va:
        ida_nalt.del_item_color(start_va)
        ida_nalt.set_item_color(start_va, color)
        start_va += idc.get_item_size(start_va)


def load_codehash_info(p_snapshot):
    """
    Load codehash info and highlight the covered code.

    :param ProcessSnapshot p_snapshot: the snapshot info
    :raise ValueError: if loading the codehashes fails for some reason
    """
    hashes = p_snapshot.hashes
    for func_hash, data in hashes.items():
        blocks_str = []
        start_function_addr = utils.va_from_string(data.get("start_addr"))
        for start_va_str, end_va_str in data.get("hash_blocks", {}).items():
            start_va = utils.va_from_string(start_va_str)
            end_va = utils.va_from_string(end_va_str)
            idc.plan_and_wait(start_va, end_va)
            create_line_color(start_va, end_va-1)
            blocks_str.append("{}-{}".format(hex(start_va), hex(end_va)))
            if start_function_addr == start_va:
                continue
            comment = "Block: {}-{} covered by function {}".format(
                hex(start_va),
                hex(end_va),
                hex(start_function_addr),
            )
            idc.set_cmt(start_va, comment, 0)
        comment = "Hash: {} - Blocks: \n{}".format(func_hash, "\n".join(blocks_str))
        idc.set_cmt(start_function_addr, comment, 0)
        ida_auto.auto_make_proc(start_function_addr)

        for start_va_str, end_va_str in data.get("same_hash_function_blocks", {}).items():
            start_va = utils.va_from_string(start_va_str)
            end_va = utils.va_from_string(end_va_str)
            idc.plan_and_wait(start_va, end_va)
            create_line_color(start_va, end_va-1)
            comment = "Hash: {} - equal to function {} \n{} - {}".format(
                func_hash,
                hex(start_function_addr),
                hex(start_va),
                hex(end_va),
            )
            idc.set_cmt(start_va, comment, 0)


def read_loader_input(li, limit=None):
    """
    Read a file from the input file.

    :param loader_input_t li: input file
    :param int|None limit: optional limit limiting the number of bytes to read
    :rtype: bytes
    :return: the file in bytes
    """
    if limit:
        li.seek(0)
        buffer = li.read(0x40)
    else:
        file_size = li.seek(0, 2)
        li.seek(0)
        buffer = li.read(file_size)
    if not buffer:
        raise ValueError("Reading snapshot failed")
    return buffer


def create_loader_file(li):
    """
    Create the loader file.

    :param loader_input_t li: input file
    :rtype: tuple(int, str)
    :return: a tuple with a file descriptor and tbhe file path
    """
    fd, filename = tempfile.mkstemp()
    buffer = read_loader_input(li)
    with open(filename, "wb") as f:
        f.write(buffer)
    return fd, filename


def accept_file(li, filename):
    """
    Checks the input file format and returns a string indicating the name if supported.

    :param loader_input_t li: input file
    :param str filename: name of the input file
    :return: name of the file format or 0 for unknown input file
    :rtype: str|int
    """
    _ = li
    try:
        version = factory.ProcessSnapshotMgrFactory.get_version(filename)
        return "Process Snapshot v{}".format(version)
    except snapshot.InvalidProcessSnapshot:
        return 0


def get_ida_bitsize():
    """Return the bitsize of IDA."""
    try:
        return IDA_BITSIZE_64 if idc.__EA64__ else IDA_BITSIZE_32
    except NameError:
        return IDA_BITSIZE_64


def validate_snapshots(snapshots, allow_32_on_64=ALLOW_32_ON_64):
    """
    Validate the snapshots and return two dictionaries detailing their validity.

    :param dict[(int, int), ProcessSnapshot]  snapshots: the list of snapshot infos
    :param bool allow_32_on_64: whether to allow IDA64 to load IDA32 snapshots
    :rtype: tuple(dict[int, ProcessSnapshot], dict[int, ProcessSnapshot])
    :return: a tuple of snapshot infos indexed by their ids
    """
    if allow_32_on_64:
        is_invalid = lambda x: get_ida_bitsize() == IDA_BITSIZE_32 and bitsize == IDA_BITSIZE_64
    else:
        is_invalid = lambda x: get_ida_bitsize() != bitsize
    valid_snapshots = {}
    invalid_snapshots = {}
    for (snapshot_id, bitsize), p_snapshot in snapshots.items():
        if is_invalid(bitsize):
            invalid_snapshots[snapshot_id] = p_snapshot
        else:
            valid_snapshots[snapshot_id] = p_snapshot
    return valid_snapshots, invalid_snapshots


def display_snapshot_info(view, valid_snapshot_by_id, invalid_snapshot_by_id):
    """
    Display all available snapshots detailing which ones are valid.

    :param simplecustviewer_t view: the cluster view
    :param dict[int, ProcessSnapshot] valid_snapshot_by_id: the valid snapshots
    :param dict[int, ProcessSnapshot] invalid_snapshot_by_id: the invalid snapshots
    """
    line = "%13s %13s %23s" % ("Snapshot Id", "Bitsize", "Analysis Reason")
    view.AddLine(ida_lines.COLSTR(line, ida_lines.SCOLOR_BINPREF))
    for snapshot_id in sorted(itertools.chain(valid_snapshot_by_id.keys(), invalid_snapshot_by_id.keys())):
        try:
            p_snapshot = valid_snapshot_by_id[snapshot_id]
            line = "%12s  %12s          %s" % (p_snapshot.snapshot_id, p_snapshot.bitsize, p_snapshot.analysis_reason)
            view.AddLine(ida_lines.COLSTR("%-80s" % line, ida_lines.SCOLOR_REG))
        except KeyError:
            p_snapshot = invalid_snapshot_by_id[snapshot_id]
            line = "%s - use IDA Pro %s bit to open this snapshot" % (line, p_snapshot.bitsize)
            view.AddLine(ida_lines.COLSTR("%-100s" % line, ida_lines.SCOLOR_ERROR))


def load_file(li, neflags, file_format_name):
    """
    Load file.

    :param loader_input_t li: input file
    :param short neflags: load file flags
    :param str file_format_name: name of type of the file as returned by 'accept_file'
    :return: 1 if the read is successful, 0 otherwise
    :rtype: int
    """
    _ = neflags, file_format_name
    fd = None
    filename = li.filename()
    if filename.startswith("<linput_t"):
        fd, filename = create_loader_file(li)
    snapshot_mgr = factory.ProcessSnapshotMgrFactory.from_file(filename)
    valid_snapshot_by_id, invalid_snapshot_by_id = validate_snapshots(snapshot_mgr.snapshots)

    ret_value = 0
    v = ida_kernwin.simplecustviewer_t()
    if v.Create("Process Snapshots"):
        display_snapshot_info(v, valid_snapshot_by_id, invalid_snapshot_by_id)
        v.Show()
        if valid_snapshot_by_id:
            while True:
                snapshot_id = ida_kernwin.ask_long(0, "Choose snapshot id from available snapshots")
                try:
                    load_snapshot(valid_snapshot_by_id[snapshot_id])
                    load_codehash_info(valid_snapshot_by_id[snapshot_id])
                    ret_value = 1
                    break
                except ValueError as ve:
                    ida_kernwin.error("Error loading snapshot %s: %s" % (snapshot_id, str(ve)))
                    continue
                except KeyError:
                    ida_kernwin.warning("Snapshot id %s is invalid! Choose a valid snapshot" % snapshot_id)
                    continue
        elif invalid_snapshot_by_id:
            ida_kernwin.error("Use IDA Pro 64 bit to open these process snapshots")
        else:
            ida_kernwin.error("The process snapshots file is invalid")

    # Cleanup
    if fd:
        os.close(fd)
    return ret_value


if __name__ == "__main__":
    """Main function."""

    class FakeLi:
        """Create a Fake Li object so the filename can be accessed."""
        def __init__(self, filename):
            """Constructor."""
            self._filename = filename

        def filename(self):
            """Method accessed by the plugin."""
            return self._filename

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s",
        "--snapshot",
        dest="snapshot",
        type=int,
        default=0,
        help="the snapshot id to parse",
    )
    parser.add_argument(
        "snapshot_file",
        default=None,
        help="snapshot file to read"
    )
    args = parser.parse_args()

    # Mock again so we can handle the case where IDA is available but we want to test the loader
    ida_auto = mock.Mock()
    ida_bytes = mock.Mock()
    ida_entry = mock.Mock()
    ida_idp = mock.Mock()
    ida_kernwin = mock.Mock()
    ida_lines = mock.Mock()
    ida_nalt = mock.Mock()
    ida_name = mock.Mock()
    ida_netnode = mock.Mock()
    ida_segment = mock.Mock()
    ida_xref = mock.Mock()
    idautils = mock.Mock()
    idc = mock.Mock()

    # Set some default values so we can test things
    ida_idp.SETPROC_LOADER_NON_FATAL = 1
    ida_idp.SETPROC_LOADER = 2
    ida_kernwin.ask_long.return_value = args.snapshot
    ida_name.SN_NOCHECK = 1
    ida_name.SN_NOWARN = 2
    idautils.Heads.return_value = []
    idc.__EA64__ = 1
    idc.get_item_size.return_value = 0x10000

    # Load the snapshot
    print("File: '{}'".format(args.snapshot_file))
    print("Snapshot: {}".format(args.snapshot))
    sys.exit(load_file(FakeLi(args.snapshot_file), 0, "Process Snapshot v3"))
