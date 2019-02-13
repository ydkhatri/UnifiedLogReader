#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''Tests for the virtual file system.'''

from __future__ import unicode_literals

import os
import unittest

from UnifiedLog import virtual_file
from UnifiedLog import virtual_file_system

from tests import test_lib


class VirtualFileSystemTests(test_lib.BaseTestCase):
    '''Tests for the virtual file system.'''

    def testPathExists(self):
        '''Tests the path_exists function.'''
        file_system = virtual_file_system.VirtualFileSystem(
            virtual_file.VirtualFile)

        path = os.path.join(
            self._TEST_DATA_PATH, '0D3C2953A33917B333DD8366AC25F2')
        result = file_system.path_exists(path)
        self.assertTrue(result)

        path = os.path.join(self._TEST_DATA_PATH, 'bogus')
        result = file_system.path_exists(path)
        self.assertFalse(result)

    def testListdir(self):
        '''Tests the listdir function.'''
        file_system = virtual_file_system.VirtualFileSystem(
            virtual_file.VirtualFile)

        expected_directory_entries = [
            '0D3C2953A33917B333DD8366AC25F2',
            '8E21CAB1DCF936B49F85CF860E6F34EC']

        directory_entries = file_system.listdir(self._TEST_DATA_PATH)
        self.assertEqual(len(directory_entries), 2)
        self.assertEqual(sorted(directory_entries), expected_directory_entries)

    def testIsDir(self):
        '''Tests the is_dir function.'''
        file_system = virtual_file_system.VirtualFileSystem(
            virtual_file.VirtualFile)

        result = file_system.is_dir(self._TEST_DATA_PATH)
        self.assertTrue(result)

        path = os.path.join(
            self._TEST_DATA_PATH, '0D3C2953A33917B333DD8366AC25F2')
        result = file_system.is_dir(path)
        self.assertFalse(result)

    def testPathJoin(self):
        '''Tests the path_join function.'''
        file_system = virtual_file_system.VirtualFileSystem(
            virtual_file.VirtualFile)

        expected_path = os.path.join(
            self._TEST_DATA_PATH, '0D3C2953A33917B333DD8366AC25F2')
        path = file_system.path_join(
            self._TEST_DATA_PATH, '0D3C2953A33917B333DD8366AC25F2')
        self.assertEqual(path, expected_path)

    def testGetVirtualFile(self):
        '''Tests the get_virtual_file function.'''
        file_system = virtual_file_system.VirtualFileSystem(
            virtual_file.VirtualFile)

        path = os.path.join(
            self._TEST_DATA_PATH, '0D3C2953A33917B333DD8366AC25F2')
        file_object = file_system.get_virtual_file(path, filetype='uuidtext')
        self.assertIsNotNone(file_object)
        self.assertIsInstance(file_object, virtual_file.VirtualFile)


if __name__ == '__main__':
    unittest.main()
