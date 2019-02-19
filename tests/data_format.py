#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''Tests for the Shared-Cache strings (dsc) file parser.'''

from __future__ import unicode_literals

import unittest

from UnifiedLog import data_format

from tests import test_lib


class BinaryDataFormat(test_lib.BaseTestCase):
    '''Tests for the binary data format.'''

    # TODO: add tests for _ReadAPFSTime

    def testReadCString(self):
        '''Tests the _ReadCString function.'''
        test_format = data_format.BinaryDataFormat()

        string = test_format._ReadCString(b'test\0bogus')
        self.assertEqual(string, 'test')

        string = test_format._ReadCString(b'\xff\xff\xff')
        self.assertEqual(string, '')

    def testReadCStringAndEndPos(self):
        '''Tests the _ReadCStringAndEndPos function.'''
        test_format = data_format.BinaryDataFormat()

        string, end_pos = test_format._ReadCStringAndEndPos(b'test\0bogus')
        self.assertEqual(string, 'test')
        self.assertEqual(end_pos, 4)

        string, end_pos = test_format._ReadCStringAndEndPos(b'\xff\xff\xff')
        self.assertEqual(string, '')
        self.assertEqual(end_pos, -1)

    # TODO: add tests for _ReadNtSid


if __name__ == '__main__':
    unittest.main()
