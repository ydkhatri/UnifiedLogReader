#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''Tests for the tracev3 file parser.'''

from __future__ import unicode_literals

import unittest
import uuid

from UnifiedLog import resources
from UnifiedLog import tracev3_file
from UnifiedLog import virtual_file
from UnifiedLog import virtual_file_system

from tests import test_lib


class TraceV3Test(test_lib.BaseTestCase):
    '''Tests for the tracev3 file parser.'''

    def _CreateTestTimesync(self):
        '''Creates a test timesync.

        Returns:
            Timesync: timesync for testing.
        '''
        timesync_header = resources.TimesyncHeader(
            b'Ts  ', 0, uuid.UUID('e955fe07-ab9d-48ec-a851-97ac5c611182'),
            0, 0, 0, 0, 0)

        return resources.Timesync(timesync_header)

    def _CreateTestFile(self):
        '''Creates a test tracev3 file.

        Returns:
            tuple[VirtualFile, TraceV3]: virtual and tracev3 file objects for
                testing.
        '''
        file_system = virtual_file_system.VirtualFileSystem(
            virtual_file.VirtualFile)

        path = self._GetTestFilePath(['0000000000000030.tracev3'])
        file_entry = virtual_file.VirtualFile(path, filetype='uuidtext')

        timesync = self._CreateTestTimesync()
        timesync_list = [timesync]

        uuidtext_path = self._GetTestFilePath([])

        test_file = tracev3_file.TraceV3(
            file_system, file_entry, timesync_list, uuidtext_path)

        return file_entry, test_file

    # TODO: add tests for _DecompressChunkData
    # TODO: add tests for _GetBootUuidTimeSyncList
    # TODO: add tests for _FindClosestTimesyncItem
    # TODO: add tests for _FindClosestTimesyncItemInList
    # TODO: add tests for _Read_CLClientManagerStateTrackerState

    def testParseChunkHeader(self):
        '''Tests the ParseChunkHeader function.'''
        file_entry, test_file = self._CreateTestFile()

        with file_entry.open() as file_object:
            chunk_header_data = file_object.read(16)

        test_file.ParseChunkHeader(chunk_header_data, 0)

    def testParseFileHeader(self):
        '''Tests the ParseFileHeader function.'''
        file_entry, test_file = self._CreateTestFile()

        with file_entry.open() as file_object:
            file_object.read(16)
            file_header_data = file_object.read(208)

        test_file.ParseFileHeader(file_header_data, 208)

    # TODO: add tests for ProcessReferencedFile

    def testProcessMetaChunk(self):
        '''Tests the ProcessMetaChunk function.'''
        file_entry, test_file = self._CreateTestFile()

        with file_entry.open() as file_object:
            file_object.read(240)
            chunk_data = file_object.read(184)

        catalog = test_file.ProcessMetaChunk(chunk_data)
        self.assertIsNotNone(catalog)
        self.assertEqual(catalog.ContinuousTime, 0)
        self.assertEqual(len(catalog.FileObjects), 0)

        expected_strings = (
            b'com.apple.AssetCache\x00builtin\x00\x00\x00\x00')
        self.assertEqual(catalog.Strings, expected_strings)

        self.assertEqual(len(catalog.ProcInfos), 1)
        self.assertEqual(len(catalog.ChunkMetaInfo), 1)

    # TODO: add tests for ReadLogDataBuffer2
    # TODO: add tests for ReadLogDataBuffer
    # TODO: add tests for RecreateMsgFromFmtStringAndData

    def testDebugPrintLog(self):
        '''Tests the DebugPrintLog function.'''
        _, test_file = self._CreateTestFile()

        test_file.DebugPrintLog(
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'msg', 0)

    def testDebugPrintTimestampFromContTime(self):
        '''Tests the DebugPrintTimestampFromContTime function.'''
        _, test_file = self._CreateTestFile()

        timesync = self._CreateTestTimesync()
        test_file.DebugPrintTimestampFromContTime(timesync, msg='msg')

    def testDebugCheckLogLengthRemaining(self):
        '''Tests the DebugCheckLogLengthRemaining function.'''
        _, test_file = self._CreateTestFile()

        test_file.DebugCheckLogLengthRemaining(0, 0, 0)

    # TODO: add tests for ProcessDataChunk
    # TODO: add tests for GetProcInfo

    def testParse(self):
        '''Tests the Parse function.'''
        file_entry, test_file = self._CreateTestFile()

        test_file.Parse()


if __name__ == '__main__':
    unittest.main()
