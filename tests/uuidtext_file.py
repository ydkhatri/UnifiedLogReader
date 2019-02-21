#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''Tests for the uuidtext file parser.'''

from __future__ import unicode_literals

import os
import unittest
import uuid

from UnifiedLog import uuidtext_file
from UnifiedLog import virtual_file

from tests import test_lib


class UuidtextTest(test_lib.BaseTestCase):
    '''Tests for the uuidtext file parser.'''

    def testParseFileObject(self):
        '''Tests the _ParseFileObject function.'''
        path = self._GetTestFilePath(['7EF56328D53A78B59CCCE3E3189F57'])
        file_entry = virtual_file.VirtualFile(path, filetype='uuidtext')

        uuid_object = uuid.UUID('{007EF563-28D5-3A78-B59C-CCE3E3189F57}')
        test_file = uuidtext_file.Uuidtext(file_entry, uuid_object)

        with open(path, 'rb') as file_object:
          test_file._ParseFileObject(file_object)

        self.assertEqual(len(test_file._entries), 1)

        expected_library_path = (
            '/System/Library/PrivateFrameworks/PhotoLibraryPrivate.framework/'
            'Versions/A/Frameworks/PhotoPrintProduct.framework/Versions/A/'
            'XPCServices/com.apple.PhotoThemeService.xpc/Contents/MacOS/'
            'com.apple.PhotoThemeService')
        self.assertEqual(test_file.library_path, expected_library_path)
        self.assertEqual(test_file.library_name, 'com.apple.PhotoThemeService')

    def testReadFmtStringFromVirtualOffset(self):
        '''Tests the ReadFmtStringFromVirtualOffset function.'''
        path = self._GetTestFilePath(['7EF56328D53A78B59CCCE3E3189F57'])
        file_entry = virtual_file.VirtualFile(path, filetype='uuidtext')

        uuid_object = uuid.UUID('{007EF563-28D5-3A78-B59C-CCE3E3189F57}')
        test_file = uuidtext_file.Uuidtext(file_entry, uuid_object)
        test_file.Parse()

        self.assertEqual(len(test_file._entries), 1)

        format_string = test_file.ReadFmtStringFromVirtualOffset(21905)
        self.assertEqual(format_string, 'system.install.apple-software')

        format_string = test_file.ReadFmtStringFromVirtualOffset(0x80000000)
        self.assertEqual(format_string, '%s')

        format_string = test_file.ReadFmtStringFromVirtualOffset(999999)
        self.assertEqual(format_string, '<compose failure [UUID]>')

        test_file._file.is_valid = False
        format_string = test_file.ReadFmtStringFromVirtualOffset(21905)
        self.assertEqual(format_string, '<compose failure [UUID]>')

    def testParse(self):
        '''Tests the Parse function.'''
        path = self._GetTestFilePath(['7EF56328D53A78B59CCCE3E3189F57'])
        file_entry = virtual_file.VirtualFile(path, filetype='uuidtext')

        uuid_object = uuid.UUID('{007EF563-28D5-3A78-B59C-CCE3E3189F57}')
        test_file = uuidtext_file.Uuidtext(file_entry, uuid_object)
        test_file.Parse()

        self.assertEqual(len(test_file._entries), 1)

        expected_library_path = (
            '/System/Library/PrivateFrameworks/PhotoLibraryPrivate.framework/'
            'Versions/A/Frameworks/PhotoPrintProduct.framework/Versions/A/'
            'XPCServices/com.apple.PhotoThemeService.xpc/Contents/MacOS/'
            'com.apple.PhotoThemeService')
        self.assertEqual(test_file.library_path, expected_library_path)
        self.assertEqual(test_file.library_name, 'com.apple.PhotoThemeService')


if __name__ == '__main__':
    unittest.main()
