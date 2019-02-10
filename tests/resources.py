#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''Tests for the resource objects.'''

from __future__ import unicode_literals

import unittest

from UnifiedLog import resources

from tests import test_lib


class CatalogTest(test_lib.BaseTestCase):
    '''Tests for the catalog.'''

    def testInitialize(self):
        '''Tests the __init__ function.'''
        test_catalog = resources.Catalog()
        self.assertIsNotNone(test_catalog)

    # TODO: add tests for GetProcInfoById


class ChunkMetaTest(test_lib.BaseTestCase):
    '''Tests for the chunk metadata.'''

    def testInitialize(self):
        '''Tests the __init__ function.'''
        test_chunk_meta = resources.ChunkMeta(0, 0, 0, 0)
        self.assertIsNotNone(test_chunk_meta)


class ExtraFileReferenceTest(test_lib.BaseTestCase):
    '''Tests for the extra file reference.'''

    def testInitialize(self):
        '''Tests the __init__ function.'''
        test_file_reference = resources.ExtraFileReference(0, 0, 0, 0, 0)
        self.assertIsNotNone(test_file_reference)


class ProcInfoTest(test_lib.BaseTestCase):
    '''Tests for the process information.'''

    def testInitialize(self):
        '''Tests the __init__ function.'''
        test_proc_info = resources.ProcInfo(
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        self.assertIsNotNone(test_proc_info)

    # TODO: add tests for GetSubSystemAndCategory


class TimesyncTest(test_lib.BaseTestCase):
    '''Tests for the timesync.'''

    def testInitialize(self):
        '''Tests the __init__ function.'''
        test_timesync = resources.Timesync(None)
        self.assertIsNotNone(test_timesync)


class TimesyncHeaderTest(test_lib.BaseTestCase):
    '''Tests for the timesync header.'''

    def testInitialize(self):
        '''Tests the __init__ function.'''
        test_header = resources.TimesyncHeader(0, 0, 0, 0, 0, 0, 0, 0)
        self.assertIsNotNone(test_header)


class TimesyncItemTest(test_lib.BaseTestCase):
    '''Tests for the timesync item.'''

    def testInitialize(self):
        '''Tests the __init__ function.'''
        test_item = resources.TimesyncItem(0, 0, 0, 0, 0)
        self.assertIsNotNone(test_item)


if __name__ == '__main__':
    unittest.main()
