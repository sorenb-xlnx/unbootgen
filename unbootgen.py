#!/usr/bin/env python3

# unbootgen - Extract Zynq boot image information
#
#  Copyright (C) 2014 Xilinx
#
#  Sören Brinkmann <soren.brinkmann@xilinx.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import os
import re
import struct
import sys

class InvalidHeaderError(Exception):
    pass

class c_header:
    def get_address(self):
        assert(self.addr)
        return self.addr

    def get_type(self):
        return self.header_type

    def _parse_header(self, fd):
        hdr = {}
        for i in range(len(self.header_entry)):
            hdr[self.header_entry[i]] = struct.unpack('I', fd.read(4))[0]
        return hdr

    def __repr__(self):
        assert(self.hdr)
        assert(len(self.hdr) == len(self.header_entry))
        string = "{}@{:x}\n".format(self.header_type, self.addr)
        for i in range(len(self.header_entry)):
            string += ("  {}: {:#x}\n".format(self.header_entry[i], int(self.hdr[self.header_entry[i]])))
        return string

class c_boot_header(c_header):
    header_entry = [
            "Width Detection",
            "Image Identification",
            "Encryption Status",
            "User Defined",
            "Source Offset",
            "Length of Image",
            "Reserved0",
            "Start of Execution",
            "Total Image Length",
            "Reserved1",
            "Header Checksum"]

    header_type = "Boot Header"

    def __init__(self, filename):
        self.image = open(filename, 'rb')
        # skip vector table
        offset = 8 * 4
        self.image.seek(offset);
        self.addr = offset
        self.hdr = self.parse_header(self.image)
        self.iht = self.parse_image_header_table(self.image)
        assert(self.hdr)
        assert(len(self.hdr) == len(self.header_entry))
        assert(self.addr)
        assert(self.iht)

    def __del__(self):
        self.image.close()

    def parse_header(self, fd):
        hdr = self._parse_header(fd)

        if hdr["Image Identification"] != 0x584C4E58:
            raise InvalidHeaderError("invalid {}".format(self.header_type))
        return hdr

    def parse_image_header_table(self, fd):
        fd.seek(0x98)   # magic offset from FSBL source code
        tmp = struct.unpack('I', fd.read(4))[0]
        iht = c_image_header_table(fd, tmp)
        return iht

    def dump_partition_by_offset(self, offset, fdout):
        part = self.find_header_by_offset(offset)
        if not part:
            print("ERROR: no partition found at offset {:x}".format(offset), file=sys.stderr)
            return None

        if part.get_type() != "Partition Header":
            print("ERROR: invalid header type for dump {}".format(part.get_type()), file=sys.stderr)
            return None

        part.dump(self.image, fdout)

    def find_header_by_offset(self, offset):
        if self.addr == offset:
            return self
        return self.iht.find_header_by_offset(offset)

class c_image_header_table(c_header):
    header_entry = [
            "Version",
            "Count of Image Headers",
            "Word Offset to Partition Header",
            "Word Offset to First Image Header",
            "Word Offset to header authentication"]

    header_type = "Image Header Table"

    def __init__(self, fd, offset):
        self.addr = offset
        fd.seek(offset);
        self.hdr = self.parse_header(fd)
        self.imgs = self.parse_images(fd)
        assert(self.hdr)
        assert(len(self.hdr) == len(self.header_entry))
        assert(self.addr)
        assert(self.imgs)

    def parse_header(self, fd):
        hdr = self._parse_header(fd)

        if hdr["Version"] != 0x01020000:
            raise InvalidHeaderError("invalid {}".format(self.header_type))
        return hdr

    def parse_images(self, fd):
        imgs = []
        tmp = self.get_image_header_offset()
        for i in range(self.get_image_count()):
            imgs.append(c_image_header(fd, tmp))
            tmp = imgs[i].get_image_header_offset()
        return imgs

    def get_image_header_offset(self):
        assert(self.hdr)
        assert(len(self.hdr) == len(self.header_entry))
        return self.hdr["Word Offset to First Image Header"] * 4

    def get_image_count(self):
        assert(self.hdr)
        assert(len(self.hdr) == len(self.header_entry))
        return self.hdr["Count of Image Headers"]

    def find_header_by_offset(self, offset):
        if self.addr == offset:
            return self
        for i in range(self.get_image_count()):
            hdr = self.imgs[i].find_header_by_offset(offset)
            if hdr:
                return hdr
        return None

class c_image_header(c_header):
    header_entry = [
            "Word Offset to Next Image Header",
            "Word Offset to First Partition Header",
            "Partition Count",
            "Image Name Length"]

    header_type = "Image Header"

    def __init__(self, fd, offset):
        self.addr = offset
        fd.seek(offset)
        self.hdr = self.parse_header(fd)
        self.image_name = self.parse_img_nm(fd)
        self.parts = self.parse_partitions(fd)
        assert(self.hdr)
        assert(len(self.hdr) == len(self.header_entry))
        assert(self.addr)
        assert(self.parts)

    def parse_header(self, fd):
        return self._parse_header(fd)

    def parse_img_nm(self, fd):
        fd.seek(self.addr + 0x10)
        string = ""
        while True:
            tmp = fd.read(4)[::-1].rstrip(b'\0').decode()
            if not tmp:
                break
            string += tmp
        return string

    def parse_partitions(self, fd):
        parts = []
        offs = self.hdr["Word Offset to First Partition Header"] * 4
        for i in range(self.get_partition_count()):
            fd.seek(offs)
            parts.append(c_partition_header(fd, offs))
            offs += 0x40
        return parts

    def get_image_header_offset(self):
        assert(self.hdr)
        assert(len(self.hdr) == len(self.header_entry))
        return self.hdr["Word Offset to Next Image Header"] * 4

    def get_partition_count(self):
        assert(self.hdr)
        assert(len(self.hdr) == len(self.header_entry))
        return self.hdr["Image Name Length"]

    def find_header_by_offset(self, offset):
        if self.addr == offset:
            return self
        for i in range(self.get_partition_count()):
            hdr = self.parts[i].find_header_by_offset(offset)
            if hdr:
                return hdr
        return None

    def __repr__(self):
        ret = super().__repr__()
        ret += "  Image Name: {}".format(self.image_name)
        return ret

class c_partition_header(c_header):
    header_entry = [
            "Partition Data Word Length",
            "Extracted Data Word Length",
            "Total Partition Word Length",
            "Destination Load Address",
            "Destination Execution Address",
            "Data Word Offset in Image",
            "Attribute Bits",
            "Section Count",
            "Checksum Word Offset",
            "Image Header Word Offset",
            "Authentication Certification Word Offset"]

    header_type = "Partition Header"

    def __init__(self, fd, offset):
        self.addr = offset
        fd.seek(offset);
        self.hdr = self.parse_header(fd)
        assert(self.hdr)
        assert(len(self.hdr) == len(self.header_entry))
        assert(self.addr)

    def parse_header(self, fd):
        return self._parse_header(fd)

    def find_header_by_offset(self, offset):
        if self.addr == offset:
            return self
        return None

    def get_partition_size(self):
        return self.hdr["Partition Data Word Length"] * 4

    def get_data_offset(self):
        return self.hdr["Data Word Offset in Image"] * 4

    def dump(self, fdin, fdout):
        fdin.seek(self.get_data_offset())
        fdout.write(fdin.read(self.get_partition_size()))

def show_header(boot_header, args):
    if args.offset:
        offset = int(args.offset, 0)
        hdr = boot_header.find_header_by_offset(offset)
        if hdr:
            print(hdr)
            return
        else:
            print("WARNING: no header found at offset {:x}".format(offset), file=sys.stderr)

    if args.all:
        print(boot_header)
        string = repr(boot_header.iht)
        string = re.sub(r'^(.)', r'\t\1', string, flags=re.MULTILINE)
        print(string)
        for image in boot_header.iht.imgs:
            string = repr(image)
            string = re.sub(r'^(.)', r'\t\t\1', string, flags=re.MULTILINE)
            print(string)
            for partition in image.parts:
                string = repr(partition)
                string = re.sub(r'^(.)', r'\t\t\t\1', string, flags=re.MULTILINE)
                print(string)
        return

def dump_partition(boot_header, args):
    offset = int(args.offset, 0)
    fdout = open(args.output, 'wb')
    boot_header.dump_partition_by_offset(offset, fdout)
    fdout.close()

# define and parse command line arguments
parser = argparse.ArgumentParser(description = "Zynq Boot Image Parser")
subparser = parser.add_subparsers()
# show command
show_parser = subparser.add_parser('show', help="Show headers")
show_parser.add_argument('input', metavar="<inputfile>", help="Input file")
show_parser.add_argument('offset', metavar="<offset>", nargs='?', help="Header offset")
show_parser.add_argument('--all', '-a', action='store_true', help="Show all headers")
show_parser.set_defaults(action=show_header)
# dump command
dump_parser = subparser.add_parser('dump', help="Dump partition")
dump_parser.add_argument('input', metavar="<inputfile>", help="Input file")
dump_parser.add_argument('offset', metavar="<offset>", help="Partition offset")
dump_parser.add_argument('output', metavar="<outputfile>", help="Output file")
dump_parser.set_defaults(action=dump_partition)

args = parser.parse_args()

boot_header = c_boot_header(args.input)
args.action(boot_header, args)
