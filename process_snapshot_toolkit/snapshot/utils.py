"""
Utils to work with Lastline Process snapshot

:Copyright:
    Copyright 2020 Lastline, Inc.  All Rights Reserved.
"""
import gzip
import tarfile


def va_from_string(value):
    """
    Convert HEX string to int
    :param str value: int as string
    :return int: virtual address
    """
    try:
        return int(value.rstrip("L"), 16)
    except ValueError:
        return 0


def extract_tar_archive(archive_path, output_dir):
    """
    Extract a tar archive into directory.

    :param str archive_path: path to a tar archive
    :param str output_dir: output directory to extract an archive
    :return: output directory
    """
    with tarfile.open(archive_path) as tar:
        
        import os
        
        def is_within_directory(directory, target):
            
            abs_directory = os.path.abspath(directory)
            abs_target = os.path.abspath(target)
        
            prefix = os.path.commonprefix([abs_directory, abs_target])
            
            return prefix == abs_directory
        
        def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
        
            for member in tar.getmembers():
                member_path = os.path.join(path, member.name)
                if not is_within_directory(path, member_path):
                    raise Exception("Attempted Path Traversal in Tar File")
        
            tar.extractall(path, members, numeric_owner=numeric_owner) 
            
        
        safe_extract(tar, output_dir)
    return output_dir


def extract_gz_archive(gz_file_path, output_file_path):
    """
    Extract a gz file.

    :param gz_file_path: path to an input gzipped file
    :param output_file_path: path to an output unzipped file
    :return: path to an output unzipped file
    """
    with gzip.open(gz_file_path, "rb") as gz_file:
        file_content = gz_file.read()
    with open(output_file_path, "wb") as output_file:
        output_file.write(file_content)
    return output_file_path
