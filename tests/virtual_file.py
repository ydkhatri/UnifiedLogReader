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
        path = self._GetTestFilePath(['LICENSE.txt'])
        file_object = virtual_file.VirtualFile(path, filetype='test')

        file_object.open()
        try:
            file_size = file_object.get_file_size()
        finally:
             file_object.close()

        self.assertEqual(file_size, 1088)


if __name__ == '__main__':
    unittest.main()
