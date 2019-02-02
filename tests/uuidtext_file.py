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

    def testParse(self):
        '''Tests the Parse function.'''
        path = self._GetTestFilePath(['0D3C2953A33917B333DD8366AC25F2'])
        file_object = virtual_file.VirtualFile(path, filetype='uuidtext')

        uuid_object = uuid.UUID('{220D3C29-53A3-3917-B333-DD8366AC25F2}')
        uuidtext = uuidtext_file.Uuidtext(file_object, uuid_object)
        uuidtext.Parse()


if __name__ == '__main__':
    unittest.main()
