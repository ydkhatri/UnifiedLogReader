#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''Tests for the virtual file object.'''

from __future__ import unicode_literals

import unittest

from UnifiedLog import virtual_file

from tests import test_lib


class VirtualFileTest(test_lib.BaseTestCase):
    '''Tests for the virtual file object.'''

    def testGetFileSize(self):
        '''Tests the get_file_size function.'''
        path = self._GetTestFilePath(['7EF56328D53A78B59CCCE3E3189F57'])
        file_entry = virtual_file.VirtualFile(path, filetype='uuidtext')

        file_entry.open()
        try:
            file_size = file_entry.get_file_size()
        finally:
            file_entry.close()

        self.assertEqual(file_size, 1100)


if __name__ == '__main__':
    unittest.main()
