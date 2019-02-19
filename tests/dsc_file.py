#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''Tests for the Shared-Cache strings (dsc) file parser.'''

from __future__ import unicode_literals

import unittest
import uuid

from UnifiedLog import dsc_file
from UnifiedLog import virtual_file

from tests import test_lib


class DscTest(test_lib.BaseTestCase):
    '''Tests for the Shared-Cache strings (dsc) file parser.'''

    def testParseFileObject(self):
        '''Tests the _ParseFileObject function.'''
        path = self._GetTestFilePath(['8E21CAB1DCF936B49F85CF860E6F34EC'])
        file_entry = virtual_file.VirtualFile(path, filetype='dsc')

        test_file = dsc_file.Dsc(file_entry)

        with open(path, 'rb') as file_object:
          self.assertTrue(test_file._ParseFileObject(file_object))

        self.assertTrue(test_file._file.is_valid)
        self.assertEqual(len(test_file.range_entries), 1)
        self.assertEqual(len(test_file.uuid_entries), 1)

    def testFindVirtualOffsetEntries(self):
        '''Tests the FindVirtualOffsetEntries function.'''
        path = self._GetTestFilePath(['8E21CAB1DCF936B49F85CF860E6F34EC'])
        file_entry = virtual_file.VirtualFile(path, filetype='dsc')

        test_file = dsc_file.Dsc(file_entry)

        test_range_entry, test_uuid_entry = test_file.FindVirtualOffsetEntries(
            0x00048a40)
        self.assertIsNone(test_range_entry)
        self.assertIsNone(test_uuid_entry)

        self.assertTrue(test_file.Parse())

        test_range_entry, test_uuid_entry = test_file.FindVirtualOffsetEntries(
            0x00048a40)
        self.assertIsNotNone(test_range_entry)
        self.assertIsNotNone(test_uuid_entry)

        test_range_entry, test_uuid_entry = test_file.FindVirtualOffsetEntries(
            0xffffffff)
        self.assertIsNone(test_range_entry)
        self.assertIsNone(test_uuid_entry)

    def testReadFmtStringAndEntriesFromVirtualOffset(self):
        '''Tests the ReadFmtStringAndEntriesFromVirtualOffset function.'''
        path = self._GetTestFilePath(['8E21CAB1DCF936B49F85CF860E6F34EC'])
        file_entry = virtual_file.VirtualFile(path, filetype='dsc')

        test_file = dsc_file.Dsc(file_entry)

        with self.assertRaises(KeyError):
            test_file.ReadFmtStringAndEntriesFromVirtualOffset(0x00048a40)

        self.assertTrue(test_file.Parse())

        test_string, test_range_entry, test_uuid_entry = (
            test_file.ReadFmtStringAndEntriesFromVirtualOffset(0x00048a40))
        self.assertEqual(test_string, '%s Unknown app vocabulary type - %@')
        self.assertIsNotNone(test_range_entry)
        self.assertIsNotNone(test_uuid_entry)

        with self.assertRaises(KeyError):
            test_file.ReadFmtStringAndEntriesFromVirtualOffset(0xffffffff)

    def testGetUuidEntryFromVirtualOffset(self):
        '''Tests the GetUuidEntryFromVirtualOffset function.'''
        path = self._GetTestFilePath(['8E21CAB1DCF936B49F85CF860E6F34EC'])
        file_entry = virtual_file.VirtualFile(path, filetype='dsc')

        test_file = dsc_file.Dsc(file_entry)

        test_uuid_entry = test_file.GetUuidEntryFromVirtualOffset(0x00030000)
        self.assertIsNone(test_uuid_entry)

        self.assertTrue(test_file.Parse())

        test_uuid_entry = test_file.GetUuidEntryFromVirtualOffset(0x00030000)
        self.assertIsNotNone(test_uuid_entry)

        test_uuid_entry = test_file.GetUuidEntryFromVirtualOffset(0xffffffff)
        self.assertIsNone(test_uuid_entry)

    def testDebugPrintDsc(self):
        '''Tests the DebugPrintDsc function.'''
        path = self._GetTestFilePath(['8E21CAB1DCF936B49F85CF860E6F34EC'])
        file_entry = virtual_file.VirtualFile(path, filetype='dsc')

        test_file = dsc_file.Dsc(file_entry)

        test_file.DebugPrintDsc()

    def testParse(self):
        '''Tests the Parse function.'''
        path = self._GetTestFilePath(['8E21CAB1DCF936B49F85CF860E6F34EC'])
        file_entry = virtual_file.VirtualFile(path, filetype='dsc')

        test_file = dsc_file.Dsc(file_entry)

        self.assertTrue(test_file.Parse())

        self.assertTrue(test_file._file.is_valid)
        self.assertEqual(len(test_file.range_entries), 1)
        self.assertEqual(len(test_file.uuid_entries), 1)


if __name__ == '__main__':
    unittest.main()
