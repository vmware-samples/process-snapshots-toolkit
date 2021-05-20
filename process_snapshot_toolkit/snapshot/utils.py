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
        tar.extractall(output_dir)
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
