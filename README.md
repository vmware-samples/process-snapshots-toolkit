# Process Snapshot Toolkit
The toolkit to work with Process Snapshots generated during dynamic analysis by VMware Anti-Malware Sandbox.

## Overview
If you are a NSX NDR (Lastline Defender) customer or a researcher using a NSX NDR (Lastline Defender) account to perform a dynamic analysis of files then one of the useful metadata type produced as a result of sandbox analysis you can access is Sandbox Process Snapshots.
The Sandbox Process Snapshots are available for most analysis subjects based on executable files in Sandbox Dynamic analysis report.
The Sandbox Process Snapshots for each subject are packed into a specifically formatted snapshot file. 
The snapshot file contains at least one (up to ten) snapshot(s) of the untrusted memory space of the process taken at certain point during dynamic execution in sandbox.

It is designed to provide a in-depth visibility into malicious code, including code which is packed/hidden in the original executable and only gets unpacked during execution.

For more details how to download Process Snapshot, please refer to the official [documentation](https://analysis.lastline.com/analysis/api-docs/html/analysis_results/format_ll_int_win.html#windows-analysis-process-dumps-pe-snapshots)

#### Installation
To install our package, please run 
```buildoutcfg
pip install process_snapshot_toolkit
```

## Ghidra postprocessing script

#### Configuration
Download the latest Ghidra from https://ghidra-sre.org/ and unpack it to chosen directory.

Using conf.ini.template create a configuration file
```
[ghidra]
path=<path to location with Ghidra decompiler location>
decompiler_script_path=<path to postprocessing script from this toolkit>
```

Postprocessing script is located here:
```
process-snapshot-toolkit/ghidra_scripts/postprocess.py
```

#### Analysis
The script is using Ghidra in the headless mode to decompile a binary and extract decompiled code as well as PCODE from an executable as well as Lastline Process Snapshot.

To decompile using the original executable file only:
```
python ghidra_analyze.py -c conf.ini -o <output_dir> --exe-file <original_executable>
```

To decompile using the original executable file and the Lastline Process Snapshot:
```
python ghidra_analyze.py -c conf.ini -o <output_dir> --exe-file <original_executable> --snapshot-file <lastline_process_snapshot>
```

#### Generated files
For each Lastline Process Snapshot, the script will generate a list of files:

**<original_executable_name>.c** - decompiled C-like code of executable.

**<original_executable_name>.called** - a list of called functions for each function found in the executable.

**<original_executable_name>.pcode** - PCODE of each function found in the executable. Mode details about PCODE format [here](https://ghidra.re/courses/languages/html/pcoderef.html)

Besides the original executable file, the output files will be generated for each snapshot found in Lastline Process Snapshot file. 
