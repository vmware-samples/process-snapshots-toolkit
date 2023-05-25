# Process Snapshot Toolkit
The toolkit to work with Process Snapshots generated during dynamic analysis by VMware Anti-Malware Sandbox.

## Overview
If you are a NSX NDR (Lastline Defender) customer or a researcher using a NSX NDR (Lastline Defender) account to perform a dynamic analysis of files then one of the useful metadata type produced as a result of sandbox analysis you can access is Sandbox Process Snapshots.
The Sandbox Process Snapshots are available for most analysis subjects based on executable files in Sandbox Dynamic analysis report.
The Sandbox Process Snapshots for each subject are packed into a specifically formatted snapshot file. 
The snapshot file contains at least one (up to ten) snapshot(s) of the untrusted memory space of the process taken at certain point during dynamic execution in sandbox.

It is designed to provide a in-depth visibility into malicious code, including code which is packed/hidden in the original executable and only gets unpacked during execution.

For more details how to download Process Snapshot, please refer to the official [documentation](https://analysis.lastline.com/analysis/api-docs/html/analysis_results/format_ll_int_win.html#windows-analysis-process-dumps-pe-snapshots)

## Installation
To install our package, please run 
```buildoutcfg
pip2 install process_snapshot_toolkit
```

Alternatively, this project can be installed via pip directly from a git clone of this repository
```
git clone <repo-url>
cd process-snapshot-toolkit
pip2 install .
```

## Development
If changes need to be made to this project, then it can be installed in a manor where it will be
usable directly from a local git repo copy.
```
# Optionally, use a virtualenv to install dependencies into, so as to not mess with system-level or
# user-level dependencies
python2 -m virtualenv venv
. venv/bin/activate

# Install dependencies needed to run the project.
pip2 install -e .

# Run tests
python2 setup.py test
```

## Analysis

#### Prerequisites
This section assumes that you've downloaded the latest Ghidra from https://ghidra-sre.org/,
unpacked it to a chosen directory, and are able to run Ghidra.

### Ghidra Code Browser
Process snapshots can be loaded into a code browser session of an exe file that the snapshot was
taken for.

#### Configuration
Inside of the Ghidra Code Browser session's Script Manager (see "Window" tab), click the
"Manage Script Directories" button (looks like a bulletpoint list). Inside the "Bundle Manager"
popup, click the "Display file chooser to add bundles list" button (looks like a green "+"). Then
select the subdirectory `ghidra/scripts` from inside wherever the process snapshot toolkit has been
installed. If you used `pip` to install process_snapshot_toolkit inside of ubuntu, then this
directory will be available via
`~/.local/lib/python2.7/site-packages/process_snapshot_toolkit/ghidra/scripts/`

#### Running
Once the directory containing the script has been added to the Code Browser's script directories,
the script `process_snapshot_loader.py` will be listed inside of the Script Manager.
Double-click this script and follow the dialog to load a snapshot file.

### Ghidra Headless
Exe files and their corresponding process snapshots can be analyzed by Ghidra in a headless fashion
to extract decompiled code, PCODE, and function call relationships between functions.

#### Configuration

Using conf.ini.template create a configuration file
```
[ghidra]
ghidra_dir=<path to location where Ghidra was unpacked>
```

#### Running
To decompile using the original executable file only:
```
ghidra_analyze.py -c conf.ini -o <output_dir> --exe-file <original_executable>
```

To decompile using the original executable file and the Lastline Process Snapshot:
```
ghidra_analyze.py -c conf.ini -o <output_dir> --exe-file <original_executable> --snapshot-file <lastline_process_snapshot>
```

#### Generated files
For each Lastline Process Snapshot, the script will generate a list of files:

**<original_executable_name>.c** - decompiled C-like code of executable.

**<original_executable_name>.called** - a list of called functions for each function found in the executable.

**<original_executable_name>.pcode** - PCODE of each function found in the executable. Mode details about PCODE format [here](https://ghidra.re/courses/languages/html/pcoderef.html)

Besides the original executable file, the output files will be generated for each snapshot found in Lastline Process Snapshot file. 
