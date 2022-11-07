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

    _CHUNK_DATA_FIREHOSE = bytes(bytearray([
        0x91, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x92, 0x37, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x10, 0x00, 0x00, 0x01, 0x02,
        0x43, 0x90, 0x98, 0x6f, 0x55, 0x00, 0x00, 0x00, 0x04, 0x10, 0x02, 0x06,
        0x10, 0xa7, 0x35, 0x00, 0x7e, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x39, 0x00, 0xf6, 0x44, 0x00, 0x00,
        0x01, 0x00, 0x15, 0x02, 0x03, 0x42, 0x04, 0x00, 0x00, 0x09, 0x00, 0x42,
        0x04, 0x09, 0x00, 0x0f, 0x00, 0x42, 0x04, 0x18, 0x00, 0x06, 0x00, 0x42,
        0x75, 0x69, 0x6c, 0x74, 0x2d, 0x69, 0x6e, 0x00, 0x43, 0x61, 0x63, 0x68,
        0x69, 0x6e, 0x67, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x00, 0x32,
        0x31, 0x34, 0x2e, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x02, 0x06, 0xf0, 0xfc, 0x35, 0x00, 0x7e, 0x6d, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x8d, 0x51, 0x4a, 0x01, 0x10, 0x00, 0x34, 0x00,
        0x13, 0x06, 0x09, 0x00, 0x01, 0x00, 0x15, 0x02, 0x01, 0x42, 0x04, 0x00,
        0x00, 0x25, 0x00, 0x45, 0x45, 0x44, 0x38, 0x46, 0x44, 0x34, 0x36, 0x2d,
        0x39, 0x36, 0x33, 0x36, 0x2d, 0x34, 0x32, 0x37, 0x34, 0x2d, 0x38, 0x46,
        0x30, 0x33, 0x2d, 0x36, 0x42, 0x37, 0x42, 0x33, 0x32, 0x39, 0x42, 0x39,
        0x39, 0x46, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x06,
        0x8c, 0xcd, 0x35, 0x00, 0x7e, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x74, 0x37, 0xb7, 0x02, 0x10, 0x00, 0xcc, 0x00, 0xdd, 0xcd, 0x03, 0x00,
        0x01, 0x00, 0x15, 0x02, 0x01, 0x42, 0x04, 0x00, 0x00, 0xbd, 0x00, 0x43,
        0x61, 0x63, 0x68, 0x65, 0x20, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72,
        0x20, 0x69, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x64,
        0x2c, 0x20, 0x63, 0x61, 0x63, 0x68, 0x65, 0x20, 0x61, 0x74, 0x20, 0x2f,
        0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2f, 0x41, 0x70, 0x70, 0x6c,
        0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x53, 0x75, 0x70, 0x70,
        0x6f, 0x72, 0x74, 0x2f, 0x41, 0x70, 0x70, 0x6c, 0x65, 0x2f, 0x41, 0x73,
        0x73, 0x65, 0x74, 0x43, 0x61, 0x63, 0x68, 0x65, 0x2f, 0x44, 0x61, 0x74,
        0x61, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x73, 0x20, 0x30,
        0x20, 0x62, 0x79, 0x74, 0x65, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x75, 0x6e,
        0x6c, 0x69, 0x6d, 0x69, 0x74, 0x65, 0x64, 0x20, 0x28, 0x69, 0x6e, 0x63,
        0x6c, 0x75, 0x64, 0x69, 0x6e, 0x67, 0x20, 0x30, 0x20, 0x62, 0x79, 0x74,
        0x65, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x75, 0x6e, 0x6c, 0x69, 0x6d, 0x69,
        0x74, 0x65, 0x64, 0x20, 0x70, 0x65, 0x72, 0x73, 0x6f, 0x6e, 0x61, 0x6c,
        0x20, 0x5b, 0x69, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x5d, 0x29, 0x2c, 0x20,
        0x61, 0x6e, 0x64, 0x20, 0x30, 0x20, 0x61, 0x66, 0x66, 0x69, 0x6e, 0x69,
        0x74, 0x79, 0x28, 0x69, 0x65, 0x73, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x10, 0x02, 0x06, 0x10, 0xb6, 0x35, 0x00, 0x7e, 0x6d, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x80, 0x16, 0xb8, 0x02, 0x10, 0x00, 0x09, 0x00,
        0xe5, 0x70, 0x01, 0x00, 0x01, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x03, 0x06, 0x90, 0xba, 0x35, 0x00,
        0x9a, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6c, 0x80, 0xc6, 0x05,
        0x10, 0x00, 0x1d, 0x00, 0x73, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0xd7, 0xdf, 0x01, 0x00, 0x01, 0x00, 0x15, 0x02, 0x01, 0x42, 0x04, 0x00,
        0x00, 0x06, 0x00, 0x77, 0x61, 0x6e, 0x74, 0x73, 0x00, 0x00, 0x00, 0x00])
    )

    def _CreateTestTimesync(self):
        '''Creates a test timesync.

        Returns:
            Timesync: timesync for testing.
        '''
        timesync_header = resources.TimesyncHeader(
            b'Ts  ', 0, uuid.UUID('e955fe07-ab9d-48ec-a851-97ac5c611182'),
            0, 0, 0, 0, 0)

        timesync_item = resources.TimesyncItem(0, 0, 0, 0, 0)

        timesync = resources.Timesync(timesync_header)
        timesync.items = [timesync_item]
        return timesync

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

    def test_ParseChunkHeaderData(self):
        '''Tests the _ParseChunkHeaderData function.'''
        file_entry, test_file = self._CreateTestFile()

        with file_entry.open() as file_object:
            chunk_header_data = file_object.read(16)

        self.assertEqual(test_file._debug_chunk_index, 0)

        tag, subtag, data_size = test_file._ParseChunkHeaderData(
            chunk_header_data, 0)

        self.assertEqual(tag, 4096)
        self.assertEqual(subtag, 17)
        self.assertEqual(data_size, 208)

        self.assertEqual(test_file._debug_chunk_index, 1)

    def testParseFileHeader(self):
        '''Tests the _ParseFileHeader function.'''
        file_entry, test_file = self._CreateTestFile()

        with file_entry.open() as file_object:
            file_object.read(16)
            file_header_data = file_object.read(208)

        test_file._ParseFileHeader(file_header_data)

        self.assertIsNotNone(test_file.system_boot_uuid)

    def testParseFileObject(self):
        '''Tests the _ParseFileObject function.'''
        path = self._GetTestFilePath(['0000000000000030.tracev3'])

        file_entry, test_file = self._CreateTestFile()

        with open(path, 'rb') as file_object:
          test_file._ParseFileObject(file_object)

    def testParseFirehoseChunkData(self):
        '''Tests the _ParseFirehoseChunkData function.'''
        file_entry, test_file = self._CreateTestFile()

        with file_entry.open() as file_object:
            file_object.read(16)
            file_header_data = file_object.read(208)
            file_object.read(16)
            test_file._ParseFileHeader(file_header_data)

            chunk_data = file_object.read(184)
            catalog = test_file._ParseMetaChunk(chunk_data)

        test_file.boot_uuid_ts_list = test_file._GetBootUuidTimeSyncList(
            test_file.ts_list,
            uuid.UUID('e955fe07-ab9d-48ec-a851-97ac5c611182'))

        proc_info = resources.ProcInfo(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        logs = []
        test_file._ParseFirehoseChunkData(
            self._CHUNK_DATA_FIREHOSE, 0, catalog, proc_info, logs)

        self.assertEqual(len(logs), 5)

    def testParseFirehoseTracepointData(self):
        '''Tests the _ParseFirehoseTracepointData function.'''
        file_entry, test_file = self._CreateTestFile()

        with file_entry.open() as file_object:
            file_object.read(16)
            file_header_data = file_object.read(208)
            file_object.read(16)
            test_file._ParseFileHeader(file_header_data)

            chunk_data = file_object.read(184)
            catalog = test_file._ParseMetaChunk(chunk_data)

        test_file.boot_uuid_ts_list = test_file._GetBootUuidTimeSyncList(
            test_file.ts_list,
            uuid.UUID('e955fe07-ab9d-48ec-a851-97ac5c611182'))

        proc_info = resources.ProcInfo(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        tracepoint_data_size, log_entry = (
            test_file._ParseFirehoseTracepointData(
                self._CHUNK_DATA_FIREHOSE[32:], 0, 0, catalog, proc_info, ''))

        self.assertEqual(tracepoint_data_size, 81)
        self.assertIsNotNone(log_entry)
        self.assertEqual(log_entry.filename, '0000000000000030.tracev3')

    def testParseMetaChunk(self):
        '''Tests the _ParseMetaChunk function.'''
        file_entry, test_file = self._CreateTestFile()

        with file_entry.open() as file_object:
            file_object.read(240)
            chunk_data = file_object.read(184)

        catalog = test_file._ParseMetaChunk(chunk_data)
        self.assertIsNotNone(catalog)
        self.assertEqual(catalog.ContinuousTime, 0)
        self.assertEqual(len(catalog.FileObjects), 2)

        expected_strings = (
            b'com.apple.AssetCache\x00builtin\x00\x00\x00\x00')
        self.assertEqual(catalog.Strings, expected_strings)

        self.assertEqual(len(catalog.ProcInfos), 1)
        self.assertEqual(len(catalog.ChunkMetaInfo), 1)

    # TODO: add tests for _ParseOversizeChunkData
    # TODO: add tests for _ParseStateChunkData

    # TODO: add tests for ProcessReferencedFile
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
