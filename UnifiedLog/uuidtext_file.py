# -*- coding: utf-8 -*-
'''The uuidtext file parser.'''

from __future__ import unicode_literals

import os

from UnifiedLog import logger


class Uuidtext(object):
    def __init__(self, v_file, uuid):
        super(Uuidtext, self).__init__()
        self.file = v_file
        self.flag1 = 0
        self.flag2 = 0
        self.num_entries = 0
        self.entries = []   # [ [range_start_offset, data_offset, data_len], [..] , ..]
        self.library_path = ''
        self.library_name = ''
        self.Uuid = uuid

    def ReadFmtStringFromVirtualOffset(self, v_offset):
        if not self.file.is_valid: return '<compose failure [UUID]>' # value returned by 'log' program if uuidtext is not found
        if v_offset & 0x80000000: return '%s' # if highest bit is set
        for entry in self.entries:
            if (entry[0] <= v_offset) and ((entry[0] + entry[2]) > v_offset):
                rel_offset = v_offset - entry[0]
                f = self.file.file_pointer
                f.seek(entry[1] + rel_offset)
                buffer = f.read(entry[2] - rel_offset)
                return ReadCString(buffer)
        #Not found
        logger.error('Invalid bounds 0x{:X} for {}'.format(v_offset, str(self.Uuid))) # This is error msg from 'log'
        return '<compose failure [UUID]>'

    def Parse(self):
        '''Parse the uuidtext file, returns True/False'''
        f = self.file.open()
        if not f:
            return False
        try:
            buffer = f.read(16) # header
            if buffer[0:4] != b'\x99\x88\x77\x66':
                logger.info('Wrong signature in uuidtext file, got 0x{} instead of 0x99887766'.format(binascii.hexlify(buffer[0:4])))
                return False
            self.flag1, self.flag2, self.num_entries = struct.unpack("<III", buffer[4:16])
            # Read entry structures
            buffer = f.read(8 * self.num_entries)
            pos = 0
            data_offset = 16 + (8 * self.num_entries)
            for i in range(self.num_entries):
                range_start_offset, data_len = struct.unpack("<II", buffer[pos:pos+8])
                self.entries.append([range_start_offset, data_offset, data_len])
                pos += 8
                data_offset += data_len
            # Read library path
            f.seek(data_offset)
            path_buffer = f.read(1024)
            self.library_path = ReadCString(path_buffer)
            self.library_name = posixpath.basename(self.library_path)

        except:
            logger.exception('Uuidtext Parser error')
            self.file.is_valid = False
        return True
