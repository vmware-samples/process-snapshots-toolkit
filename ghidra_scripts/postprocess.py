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
sys.path.append("/usr/local/lib/python2.7/dist-packages")
sys.path.append("/usr/lib/python2.7/dist-packages")
sys.path.append(
    "{}/.local/lib/python2.7/site-packages/".format(os.path.expanduser("~"))
)

from process_snapshot_toolkit.snapshot import factory
from process_snapshot_toolkit.snapshot import utils

print(factory.__file__)
try:
    import ghidra.program.model.symbol as symbol
    import ghidra.program.model.address as address
    import ghidra.program.model.pcode as pcode
    import ghidra.app.decompiler as m_decompiler
except ImportError as err:
    logger.error(
        "Ghidra postprocessing script cannot be run stand alone and needs to be run "
        "as part of Ghidra headless analysis. Error: %s",
        err,
    )


class Error(Exception):
    """
    Base-class for all exceptions in this module
    """


try:
    # global Ghidra objects provided by Ghidra
    functionManager = currentProgram.getFunctionManager()
    externalManager = currentProgram.getExternalManager()
    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()
except NameError as err:
    logger.error(
        "Ghidra postprocessing script cannot be run stand alone and needs to be run "
        "as part of Ghidra headless analysis. Error: %s",
        err,
    )


def cleanup_memory_space():
    """
    Cleans up Ghidra memory space:
        * removes all memory blocks
        * removes all functions

    :return None:
    """
    for seg in memory.getBlocks():
        # functionManager.deleteAddressRange(seg.getStart(), seg.getEnd(), monitor)
        memory.removeBlock(seg, monitor)


def map_library_export(lib_ext, export_name, export_va):
    """
    Map Library Export into Address space.
    :param ghidra.program.model.listing.Library lib_ext: external library object created by Ghidra
        for the library in address space
    :param str export_name: name of the exported function
    :param int export_va: virtual address of the exported function
    :return ghidra.program.model.listing.Function: Ghidra function object if
        the export was correctly mapped. Otherwise None
    """
    try:
        export_addr = toAddr(export_va)
        ext_location = currentProgram.getExternalManager().addExtFunction(
            lib_ext, export_name, export_addr, symbol.SourceType.IMPORTED
        )

        export_func = functionManager.getFunctionAt(export_addr)
        if export_func:
            export_func.setName(export_name, symbol.SourceType.IMPORTED)
        else:
            export_func = functionManager.createFunction(
                export_name,
                export_addr,
                address.AddressSet(export_addr),
                symbol.SourceType.IMPORTED,
            )

        if export_func and ext_location:
            export_func.setThunkedFunction(ext_location.getFunction())
        return export_func

    except Error:
        logger.error("Failed to add %s. Exception: %s", export_name, sys.exc_info()[0])


def map_loaded_library(library):
    """
    Maps a library from Lastline process snapshot into
        Ghidra memory space.

    :param process_snapshot_toolkit.snapshot.LoadedLibrary library: a loaded
        library object from Lastline process snapshot
    :return ghidra.program.model.listing.Library: external library object created
        for the library in Ghidra
    """
    try:
        lib_addr = toAddr(library.virtual_address)
        lib_ext = externalManager.getExternalLibrary(library.name)
        if not lib_ext:
            lib_ext = currentProgram.getSymbolTable().createExternalLibrary(
                library.name, symbol.SourceType.IMPORTED
            )

        library_block = memory.getBlock(lib_addr)
        if not library_block:
            library_block = memory.createUninitializedBlock(
                library.name, lib_addr, library.size, False
            )
        return lib_ext
    except Error as err:
        logger.error("Failed to map library %s: %s", library.name, err)


def map_loaded_libraries(snapshot):
    """
    Maps all libraries from Lastline process snapshot into
        Ghidra memory space.

    :param process_snapshot_toolkit.snapshot. ProcessSnapshot snapshot: a snapshot
        object from Lastline process snapshot.
    :return None:
    """
    if not snapshot.loaded_libs:
        return
    try:
        for library in snapshot.loaded_libs:
            lib_addr = toAddr(library.virtual_address)
            lib_ext = externalManager.getExternalLibrary(library.name)
            if not lib_ext:
                lib_ext = currentProgram.getSymbolTable().createExternalLibrary(
                    library.name, symbol.SourceType.IMPORTED
                )

            library_block = memory.getBlock(lib_addr)
            if not library_block:
                library_block = memory.createUninitializedBlock(
                    library.name, lib_addr, library.size, False
                )
    except Error as err:
        logger.error("Failed to map library %s: %s", library.name, err)


def map_memory_blocks(snapshot):
    """
    Maps all memory blocks from Lastline process snapshot into
        Ghidra memory space.

    :param process_snapshot_toolkit.snapshot. ProcessSnapshot snapshot: a snapshot
        object from Lastline process snapshot.
    :param snapshot:
    :return: None
    """
    if not snapshot.memory_blocks:
        return

    try:
        for block in snapshot.memory_blocks:
            block_addr = toAddr(block.virtual_address)
            memory_block = memory.createUninitializedBlock(
                block.object_uuid, block_addr, block.size, False
            )
            memory.convertToInitialized(memory_block, 0)
            memory_block.setRead(block.is_read)
            memory_block.setExecute(block.is_execute)
            memory.setBytes(block_addr, block.data)

            for entry_point in block.entry_points:
                entry_point_va = entry_point + block.virtual_address
                entry_point_addr = toAddr(entry_point_va)

                addEntryPoint(entry_point_addr)
                func_name = "FUN_{:08X}".format(entry_point_va)
                func_ep = createFunction(entry_point_addr, func_name)
                if not func_ep:
                    logger.error(
                        "Failed to create function: %s at 0x%08X",
                        func_name,
                        entry_point_va,
                    )
                else:
                    logger.info(
                        "Created function: %s at 0x%08X", func_name, entry_point_va
                    )
                    disassemble(entry_point_addr)

    except Error as err:
        logger.error("Failed to load memory blocks: %s", err)


def map_pe_images(snapshot):
    """
    Maps all PE images from Lastline process snapshot into
        Ghidra memory space.

    :param process_snapshot_toolkit.snapshot. ProcessSnapshot snapshot: a snapshot
        object from Lastline process snapshot.
    :param snapshot:
    :return: None
    """
    if not snapshot.pe_images:
        return

    try:
        for pe_image in snapshot.pe_images:
            if not pe_image.sections:
                createMemoryBlock(
                    pe_image.name,
                    toAddr(pe_image.virtual_address),
                    pe_image.data,
                    pe_image.size,
                )
            else:
                pe_header_size = 0x1000
                for section in pe_image.sections:
                    if (
                        section.virtual_address >= pe_image.virtual_address
                        and pe_header_size
                        > section.virtual_address - pe_image.virtual_address
                    ):
                        pe_header_size = (
                            section.virtual_address - pe_image.virtual_address
                        )
                    section_memory_block = memory.createUninitializedBlock(
                        section.name,
                        toAddr(section.virtual_address),
                        section.size,
                        False,
                    )
                    memory.convertToInitialized(section_memory_block, 0)
                    memory.setBytes(toAddr(section.virtual_address), section.data)
                    section_memory_block.setRead(section.is_read)
                    if section.is_execute:
                        section_memory_block.setExecute(True)
                        createFunction(toAddr(section.virtual_address), section.name)
                        addEntryPoint(toAddr(section.virtual_address))
                        disassemble(toAddr(section.virtual_address))

                    for entry_point in section.entry_points:
                        entry_point_va = entry_point + pe_image.virtual_address
                        entry_point_addr = toAddr(entry_point_va)
                        addEntryPoint(entry_point_addr)
                        func_name = "FUN_{:08X}".format(entry_point_va)
                        func_ep = createFunction(entry_point_addr, func_name)
                        if not func_ep:
                            logger.error(
                                "Failed to create function: %s from entry point at 0x%08X",
                                func_name,
                                entry_point_va,
                            )
                        else:
                            logger.info(
                                "Created function: %s at 0x%08X",
                                func_name,
                                entry_point_va,
                            )
                            disassemble(entry_point_addr)

                if pe_header_size:
                    createMemoryBlock(
                        pe_image.name,
                        toAddr(pe_image.virtual_address),
                        pe_image.data,
                        pe_header_size,
                    )

            if pe_image.entry_point:
                entry_point_va = pe_image.entry_point + pe_image.virtual_address
                addEntryPoint(toAddr(entry_point_va))
                func_name = "FUN_{:08X}".format(entry_point_va)
                func_ep = createFunction(toAddr(entry_point_va), func_name)
                if not func_ep:
                    logger.error(
                        "Failed to create function: %s at 0x%08X",
                        func_name,
                        entry_point_va,
                    )
                else:
                    disassemble(toAddr(entry_point_va))
    except Error as err:
        logger.error("Failed to load pe images")


def analyze_and_map_va(va, snapshot):
    """
    Analyze a given VA against a Lastline process snapshot
    and map library/function in case if VA points to them
    :param va: virtual address in process memory space
    :param snapshot: Lastline process snapshot
    :return: True, if VA belongs to the loaded library
    """
    lib = snapshot.get_lib(va)
    if not lib:
        return False

    if va not in lib.exports:
        return False

    lib_ext = map_loaded_library(lib)
    if not lib_ext:
        return False

    map_library_export(lib_ext, lib.exports[va].name, va)
    return True


def load_snapshot(decomp, snapshot):
    """
    Map and Decompile Lastline Snapshot
    :param decompiler.DecompInterface decomp: decompiler interface
    :param file_decompiler.process_snapshot.LastlineProcessSnapshot snapshot:
        Lastline Snapshot
    :return: True if succeeded. Otherwise False
    :rvalue: boolean
    """
    try:
        cleanup_memory_space()

        # load memory and analyze to build a callgraph
        map_pe_images(snapshot)
        map_memory_blocks(snapshot)
        analyzeAll(currentProgram)

        # using a callgraph find used exports and rename/created them
        for func in functionManager.getFunctions(toAddr(0), True):
            tokengrp = decomp.decompileFunction(func, 0, monitor)
            if not tokengrp:
                continue

            high_func = tokengrp.getHighFunction()
            if not high_func:
                continue

            for op in high_func.getPcodeOps():
                opcode = op.getOpcode()
                if (
                    opcode == pcode.PcodeOp.CALL
                    or opcode == pcode.PcodeOp.BRANCH
                    or opcode == pcode.PcodeOp.CALLIND
                    or opcode == pcode.PcodeOp.PTRSUB
                    or opcode == pcode.PcodeOp.PTRADD
                    or opcode == pcode.PcodeOp.BRANCHIND
                ):
                    for op_input in op.getInputs():
                        branch_va = op_input.getOffset()
                        analyze_and_map_va(branch_va, snapshot)
        analyzeAll(currentProgram)

        # map the rest of the libraries to the address space and
        # rename functions which belong to them
        map_loaded_libraries(snapshot)
        for func in functionManager.getFunctions(True):
            analyze_and_map_va(func.getEntryPoint().getOffset(), snapshot)
        analyzeAll(currentProgram)

        return True

    except Error as err:
        logger.error("Failed to load snapshot %d. Error: %s", snapshot.snapshot_id, err)
    return False


def extract_decompiled_functions(decomp, output_filepath, snapshot=None):
    """
    Extracts decompiled code of all functions to output file
    :param decomp: Ghida decompiler object
    :param output_filepath: a path to output file
    :param snapshot: Lastline process snapshot
    :return: None
    """
    try:
        with open(output_filepath, "w") as output_file:
            for func in functionManager.getFunctions(toAddr(0), True):
                try:
                    if snapshot and snapshot.get_lib(
                        utils.va_from_string(func.entryPoint.toString())
                    ):
                        continue

                    tokengrp = decomp.decompileFunction(func, 0, monitor)
                    if not tokengrp:
                        continue

                    decompiled_func = tokengrp.getDecompiledFunction()
                    if not decompiled_func:
                        continue

                    output_file.write(
                        u"{}\n".format(
                            decompiled_func.getC()
                            .encode("ascii", "ignore")
                            .decode("ascii")
                        )
                    )

                except Error as err:
                    logger.error(
                        "Failed to decompile function: %s. Error: %s",
                        func.getName(),
                        err,
                    )
    except Error as err:
        logger.error(
            "Failed decompiled functions extraction to %s. Error: %s",
            output_filepath,
            err,
        )


def extract_called_functions(output_filepath, snapshot=None):
    """
    Extracts a list of called functions for each function
    to the output file
    :param output_filepath: a path to output file
    :param snapshot: Lastline process snapshot
    :return: None
    """
    try:
        with open(output_filepath, "w") as output_file:
            for func in functionManager.getFunctions(toAddr(0), True):
                try:
                    if snapshot and snapshot.get_lib(
                        utils.va_from_string(func.entryPoint.toString())
                    ):
                        continue

                    called_func = func.getCalledFunctions(monitor)
                    if not called_func:
                        continue

                    output_file.write(u"{}: {}\n".format(func.entryPoint, called_func))
                except Error as err:
                    logger.error(
                        "Failed to process function: %s. Error: %s", func.getName(), err
                    )
    except Error as err:
        logger.error(
            "Failed to extraced called functions to %s. Error: %s", output_filepath, err
        )


def extract_pcode_functions(decomp, output_filepath, snapshot=None):
    """
    Extracts PCODE of the functions to provided file
    :param decomp: Ghidra decompiler object
    :param output_filepath: path to output file
    :param snapshot: Lastline process snapshot
    :return: None
    """
    try:
        with open(output_filepath, "w") as output_file:
            for func in functionManager.getFunctions(toAddr(0), True):
                try:
                    if snapshot and snapshot.get_lib(
                        utils.va_from_string(func.entryPoint.toString())
                    ):
                        continue

                    tokengrp = decomp.decompileFunction(func, 0, monitor)
                    if not tokengrp:
                        continue

                    output_file.write(
                        u"start {} at {}\n".format(func.getName(), func.getEntryPoint())
                    )
                    func_branch = dict()
                    func_loop = dict()
                    branch_index = 0
                    branch_done = set()

                    high_func = tokengrp.getHighFunction()
                    if not high_func:
                        continue

                    for op in high_func.getPcodeOps():
                        if op.getOpcode() == pcode.PcodeOp.CBRANCH:
                            target_addr = op.getSeqnum().getTarget()
                            branch_addr = op.getInput(0).getAddress()
                            if branch_addr < target_addr:
                                func_loop[branch_addr] = branch_index
                            else:
                                func_branch[branch_addr] = branch_index
                            branch_index = branch_index + 1

                    for op in high_func.getPcodeOps():
                        target_addr = op.getSeqnum().getTarget()
                        if target_addr not in branch_done:
                            if target_addr in func_branch:
                                output_file.write(
                                    u"{}:\n".format(func_branch[target_addr])
                                )
                                branch_done.add(target_addr)
                            if target_addr in func_loop:
                                output_file.write(
                                    u"loop start {}:\n".format(func_loop[target_addr])
                                )
                                branch_done.add(target_addr)

                            if op.getOpcode() == pcode.PcodeOp.CBRANCH:
                                branch_addr = op.getInput(0).getAddress()
                                if branch_addr in func_loop:
                                    output_file.write(
                                        u"loop end {} (start at {})\n".format(
                                            func_loop[branch_addr], branch_addr
                                        )
                                    )
                                    branch_done.add(target_addr)
                                elif branch_addr in func_branch:
                                    output_file.write(
                                        u"jump to {} ({})\n".format(
                                            func_branch[branch_addr], branch_addr
                                        )
                                    )
                                    branch_done.add(target_addr)

                        # if op.getOpcode() == pcode.PcodeOp.CALL:
                        output_file.write(
                            u"   {} {}({}) {}\n".format(
                                target_addr,
                                op.getMnemonic(),
                                op.getOpcode(),
                                op.getInputs(),
                            )
                        )
                    output_file.write(u"\n\n")
                except Error as err:
                    logger.error(
                        "Failed to process function: %s. Error: %s", func.getName(), err
                    )
    except Error as err:
        logger.error(
            "Failed to extraced called functions to %s. Error: %s", output_filepath, err
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
    extract_decompiled_functions(decomp, source_path)

    extract_called_functions(
        os.path.join(args.output_dir, "{}.called".format(executable_name))
    )
    extract_pcode_functions(
        decomp, os.path.join(args.output_dir, "{}.pcode".format(executable_name))
    )

    if args.snapshot_file:
        snapshot_manager = factory.ProcessSnapshotMgrFactory.from_file(
            args.snapshot_file
        )
        for (snapshot_id, bitsize), snapshot in snapshot_manager.snapshots.items():
            logger.info("Processing snapshot id: %d bitsize: %d", snapshot_id, bitsize)
            if not load_snapshot(decomp, snapshot):
                continue
            dst_name = "{}_{}_{}".format(
                os.path.basename(args.snapshot_file), snapshot_id, bitsize
            )
            source_path = os.path.join(args.output_dir, "{}.c".format(dst_name))
            extract_decompiled_functions(decomp, source_path, snapshot)
            extract_called_functions(
                os.path.join(args.output_dir, "{}.called".format(dst_name)), snapshot
            )
            extract_pcode_functions(
                decomp,
                os.path.join(args.output_dir, "{}.pcode".format(dst_name)),
                snapshot,
            )


try:
    args = getScriptArgs()
    do_postprocess(getScriptArgs())
except NameError as err:
    logger.error(
        "Ghidra postprocessing script cannot be run stand alone and needs to be run "
        "as part of Ghidra headless analysis. Error: %s",
        err,
    )
