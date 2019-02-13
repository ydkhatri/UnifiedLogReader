# -*- coding: utf-8 -*-
'''The Shared-Cache strings (dsc) file parser.'''

from __future__ import unicode_literals

import os
import posixpath
import struct
import uuid

from UnifiedLog import logger


class Dsc(object):
    def __init__(self, v_file):
        super(Dsc, self).__init__()
        self.file = v_file
        self.version = 0
        self.num_range_entries = 0
        self.num_uuid_entries = 0
        self.range_entries = []  # [ [uuid_index, v_off, data_offset, data_len], [..], ..] # data_offset is absolute in file
        self.uuid_entries  = []  # [ [v_off,  size,  uuid,  lib_path, lib_name], [..], ..] # v_off is virt offset

    # TODO: move this into a shared DataFormat class.
    def _ReadCString(self, data, max_len=1024):
        '''Returns a C utf8 string (excluding terminating null)'''
        pos = 0
        max_len = min(len(data), max_len)
        string = ''
        try:
            null_pos = data.find(b'\x00', 0, max_len)
            if null_pos == -1:
                logger.warning("Possible corrupted string encountered")
                string = data.decode('utf8')
            else:
                string = data[0:null_pos].decode('utf8')
        except:
            logger.exception('Error reading C-String')

        return string

    def FindVirtualOffsetEntries(self, v_offset):
        '''Return tuple (range_entry, uuid_entry) where range_entry[xx].size <= v_offset'''
        ret_range_entry = None
        ret_uuid_entry = None
        for a in self.range_entries:
            if (a[1] <= v_offset) and ((a[1] + a[3]) > v_offset):
                ret_range_entry = a
                ret_uuid_entry = self.uuid_entries[a[0]]
                return (ret_range_entry, ret_uuid_entry)
        #Not found
        logger.error('Failed to find v_offset in Dsc!')
        return (None, None)

    def ReadFmtStringAndEntriesFromVirtualOffset(self, v_offset):
        '''Reads the format string, range and UUID entry for a specific offset.

        Args:
          v_offset (int): virtual (or dsc range) offset.

        Returns:
          tuple: that contains:
            str: format string.
            tuple[int, int, int, int]: range entry.
            tuple[int, int, uuid.UUID, str, str]: UUID entry.

        Raises:
          KeyError: if no range entry could be found corresponding the offset.
          IOError: if the format string cannot be read.
        '''
        range_entry, uuid_entry = self.FindVirtualOffsetEntries(v_offset)
        if not range_entry:
            raise KeyError('Missing range entry for offset: 0x{0:08x}'.format(
                v_offset))

        rel_offset = v_offset - range_entry[1]
        f = self.file.file_pointer
        f.seek(range_entry[2] + rel_offset)
        cstring_data = f.read(range_entry[3] - rel_offset)
        cstring = self._ReadCString(cstring_data)
        return cstring, range_entry, uuid_entry

    # TODO: Per https://github.com/ydkhatri/UnifiedLogReader/issues/15 this
    # method is deprecated remove
    def GetUuidEntryFromUuid(self, uuid):
        '''Find a uuid_entry from its UUID value'''
        for b in self.uuid_entries:
            if b[2] == uuid:
                return b
        #Not found
        logger.error('Failed to find uuid {} in Dsc!'.format(str(uuid)))
        return None

    def GetUuidEntryFromVirtualOffset(self, v_offset):
        '''Returns uuid_entry where uuid_entry[xx].v_off <= v_offset and falls within allowed size'''
        for b in self.uuid_entries:
            if (b[0] <= v_offset) and ((b[0] + b[1]) > v_offset):
                rel_offset = v_offset - b[0]
                return b
        #Not found
        logger.error('Failed to find uuid_entry for v_offset 0x{:X} in Dsc!'.format(v_offset))
        return None

    def DebugPrintDsc(self):
        logger.debug("DSC version={} file={}".format(self.version, self.file.filename))
        logger.debug("Range entry values")
        for a in self.range_entries:
            logger.debug("{} {} {} {}".format(a[0], a[1], a[2], a[3]))
        logger.debug("Uuid entry values")
        for b in self.uuid_entries:
            logger.debug("{} {} {} {} {}".format(b[0], b[1], b[2], b[3], b[4]))

    def Parse(self):
        '''Parse the dsc file, returns True/False'''
        f = self.file.open()
        if not f:
            return False
        try:
            buffer = f.read(16) # header
            if buffer[0:4] != b'hcsd':
                logger.info('Wrong signature in DSC file, got 0x{} instead of 0x68637364 (hcsd)'.format(binascii.hexlify(buffer[0:4])))
                return False
            self.version, self.num_range_entries, self.num_uuid_entries = struct.unpack("<III", buffer[4:16])
            # Read range structures
            buffer = f.read(16 * self.num_range_entries)
            pos = 0
            for i in range(self.num_range_entries):
                uuid_index, v_off, data_offset, data_len = struct.unpack("<IIII", buffer[pos:pos+16])
                self.range_entries.append([uuid_index, v_off, data_offset, data_len])
                pos += 16
            # Read uuid_entry structures
            buffer = f.read(28 * self.num_uuid_entries)
            pos = 0
            for i in range(self.num_uuid_entries):
                v_off, size = struct.unpack("<II", buffer[pos:pos+8])
                uuid_object = uuid.UUID(bytes=buffer[pos+8:pos+24])
                data_offset = struct.unpack("<I", buffer[pos+24:pos+28])[0]
                f.seek(data_offset)
                path_buffer = f.read(1024) # File path should not be >1024
                lib_path = self._ReadCString(path_buffer)
                lib_name = posixpath.basename(lib_path)
                self.uuid_entries.append([v_off, size, uuid_object, lib_path, lib_name])
                pos += 28
        except (IOError, OSError, struct.error):
            logger.exception('DSC Parser error')
            self.file.is_valid = False
        return True
