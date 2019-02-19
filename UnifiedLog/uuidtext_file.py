# -*- coding: utf-8 -*-
'''The uuidtext file parser.'''

from __future__ import unicode_literals

import struct
import os
import posixpath

from UnifiedLog import data_format
from UnifiedLog import logger


class Uuidtext(data_format.BinaryDataFormat):
    '''Uuidtext file parser.'''

    def __init__(self, v_file, uuid):
        '''Initializes an uuidtext file parser.

        Args:
          v_file (VirtualFile): a virtual file.
          uuid (uuid.UUID): an UUID.
        '''
        super(Uuidtext, self).__init__()
        self._file = v_file
        self.entries = []   # [ [range_start_offset, data_offset, data_len], [..] , ..]
        self.library_path = ''
        self.library_name = ''
        self.Uuid = uuid

    def _ParseFileObject(self, file_object):
        '''Parses an uuidtext file-like object.

        Args:
          file_object (file): file-like object.

        Returns:
          bool: True if the uuidtext file-like object was successfully parsed,
              False otherwise.

        Raises:
          IOError: if the uuidtext file cannot be parsed.
          OSError: if the uuidtext file cannot be parsed.
          struct.error: if the uuidtext file cannot be parsed.
        '''
        file_header_data = file_object.read(16)
        if file_header_data[0:4] != b'\x99\x88\x77\x66':
            signature_base16 = binascii.hexlify(file_header_data[0:4])
            logger.info((
                'Wrong signature in uuidtext file, got 0x{} instead of '
                '0x99887766').format(signature_base16))
            return False

        # Note that the flag1 and flag2 are not used.
        flag1, flag2, num_entries = struct.unpack(
            "<III", file_header_data[4:16])

        entries_data_size = 8 * num_entries
        entries_data = file_object.read(entries_data_size)

        entry_offset = 0
        data_offset = 16 + entries_data_size
        while len(self.entries) < num_entries:
            entry_end_offset = entry_offset + 8
            range_start_offset, data_len = struct.unpack(
                "<II", entries_data[entry_offset:entry_end_offset])

            entry_offset = entry_end_offset

            self.entries.append([range_start_offset, data_offset, data_len])
            data_offset += data_len

        file_object.seek(data_offset, os.SEEK_SET)
        library_path_data = file_object.read(1024)
        self.library_path = self._ReadCString(library_path_data)
        self.library_name = posixpath.basename(self.library_path)

        return True

    def ReadFmtStringFromVirtualOffset(self, v_offset):
        if not self._file.is_valid:
            return '<compose failure [UUID]>' # value returned by 'log' program if uuidtext is not found

        if v_offset & 0x80000000:
            return '%s' # if highest bit is set

        for entry in self.entries:
            if (entry[0] <= v_offset) and ((entry[0] + entry[2]) > v_offset):
                rel_offset = v_offset - entry[0]
                f = self._file.file_pointer
                f.seek(entry[1] + rel_offset)
                buffer = f.read(entry[2] - rel_offset)
                return self._ReadCString(buffer)

        #Not found
        logger.error('Invalid bounds 0x{:X} for {}'.format(v_offset, str(self.Uuid))) # This is error msg from 'log'
        return '<compose failure [UUID]>'

    def Parse(self):
        '''Parses a uuidtext file.

        self._file.is_valid is set to False if this method encounters issues
        parsing the file.

        Returns:
          bool: True if the dsc file-like object was successfully parsed,
              False otherwise.
        '''
        file_object = self._file.open()
        if not file_object:
          return False

        try:
            result = self._ParseFileObject(file_object)
        except (IOError, OSError, struct.error):
            logger.exception('Uuidtext Parser error')
            result = False

        if not result:
            self._file.is_valid = False

        return result
