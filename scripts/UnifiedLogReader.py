#!/usr/bin/env python
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Unified log reader
# Copyright (c) 2018  Yogesh Khatri <yogesh@swiftforensics.com> (@swiftforensics)
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Script Name  : UnifiedLogReader.py
# Author       : Yogesh Khatri
# Last Updated : 2020-01-24
# Purpose/Usage: This script will read unified logs. Tested on python 3.7
#
# Notes:
# Currently this is tested on version 17(0x11) of the tracev3 file used in
# macOS Sierra (10.12.5) and above (including Catalina 10.15). It will not
# work on Sierra (10.12) as it uses version 14(0xE), a later update will
# address this. Also tested on iOS 12.4 logs.
#

import abc
import argparse
import codecs
import logging
import io
import os
import sqlite3
import sys
import time

import UnifiedLog

from UnifiedLog import Lib as UnifiedLogLib
from UnifiedLog import logger
from UnifiedLog import tracev3_file
from UnifiedLog import virtual_file
from UnifiedLog import virtual_file_system


class OutputWriter(object):
    '''Output writer interface.'''

    @abc.abstractmethod
    def Close(self):
        '''Closes the output writer.'''

    @abc.abstractmethod
    def Open(self):
        '''Opens the output writer.

        Returns:
          bool: True if successful or False on error.
        '''

    @abc.abstractmethod
    def WriteLogEntries(self, logs):
        '''Writes several Unified Log entries.

        Args:
          logs (???): list of log entries:
        '''

    @abc.abstractmethod
    def WriteLogEntry(self, log):
        '''Writes a Unified Log entry.

        Args:
          log (???): log entry:
        '''


class SQLiteDatabaseOutputWriter(object):
    '''Output writer that writes output to a SQLite database.'''

    _CREATE_LOGS_TABLE_QUERY = (
        'CREATE TABLE logs (SourceFile TEXT, SourceFilePos INTEGER, '
        'ContinuousTime TEXT, TimeUtc TEXT, Thread INTEGER, Type TEXT, '
        'ActivityID INTEGER, ParentActivityID INTEGER, ProcessID INTEGER, '
        'EffectiveUID INTEGER, TTL INTEGER, ProcessName TEXT, '
        'SenderName TEXT, Subsystem TEXT, Category TEXT, SignpostName TEXT, '
        'SignpostInfo TEXT, ImageOffset INTEGER, SenderUUID TEXT, '
        'ProcessImageUUID TEXT, SenderImagePath TEXT, ProcessImagePath TEXT, '
        'Message TEXT)')

    _INSERT_LOGS_VALUES_QUERY = (
        'INSERT INTO logs VALUES '
        '(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')

    def __init__(self, path):
        '''Initializes a SQLite database output writer.

        Args:
          path (str): path of the SQLite database file.
        '''
        super(SQLiteDatabaseOutputWriter, self).__init__()
        self._connection = None
        self._path = path

    def Close(self):
        '''Closes the unified logs reader.'''
        if self._connection:
            try:
                self._connection.commit()
                self._connection.close()

            except sqlite3.Error:
                logger.exception('Unable to close database')

            self._connection = None

        self._path = None

    def Open(self):
        '''Opens the output writer.'''
        if os.path.exists(self._path):
            try:
                logger.info('Database already exists, trying to delete it.')
                os.remove(self._path)

            except (IOError, OSError):
                logger.exception(
                    'Unable to remove existing database at %s.', self._path)
                return False

        try:
            logger.info('Trying to create new database file at %s.', self._path)
            self._connection = sqlite3.connect(self._path)

            cursor = self._connection.cursor()
            cursor.execute(self._CREATE_LOGS_TABLE_QUERY)

        except sqlite3.Error:
            logger.exception('Failed to create database at %s', self._path)
            return False

        return True

    def WriteLogEntries(self, logs):
        '''Writes several Unified Log entries.

        Args:
          logs (???): list of log entries:
        '''
        if self._connection:
            for log in logs:
                log[3] = UnifiedLogLib.ReadAPFSTime(log[3])
                log[18] = '{0!s}'.format(log[18])
                log[19] = '{0!s}'.format(log[19])

            # TODO: cache queries to use executemany
            try:
                cursor = self._connection.cursor()
                cursor.executemany(self._INSERT_LOGS_VALUES_QUERY, logs)
                self._connection.commit()

            except sqlite3.Error:
                logger.exception('Error inserting data into database')


    def WriteLogEntry(self, log):
        '''Writes a Unified Log entry.

        Args:
          log (???): log entry:
        '''
        self.WriteLogEntries([log])


class FileOutputWriter(object):
    '''Output writer that writes output to a file.'''

    _HEADER_ALL = '\t'.join([
        'SourceFile', 'LogFilePos', 'ContinousTime', 'Time', 'ThreadId',
        'LogType', 'ActivityId', 'ParentActivityId', 'PID', 'EUID', 'TTL',
        'ProcessName', 'SenderName', 'Subsystem', 'Category', 'SignpostName',
        'SignpostString', 'ImageOffset', 'ImageUUID', 'ProcessImageUUID',
        'SenderImagePath', 'ProcessImagePath', 'LogMessage'])

    _HEADER_DEFAULT = (
        'Timestamp                  Thread     Type        '
        'Activity             PID    TTL  Message')

    def __init__(self, path, mode='LOG_DEFAULT'):
        '''Initializes a file output writer.

        Args:
          path (str): path of the file.
          mode (Optional[str]): output mode, which can be LOG_DEFAULT or TSV_ALL.

        Raises:
          ValueError: if mode is unsupported.
        '''
        if mode not in ('TSV_ALL', 'LOG_DEFAULT'):
            raise ValueError('Unsupported mode')

        super(FileOutputWriter, self).__init__()
        self._file_object = None
        self._mode = mode
        self._path = path

    def Close(self):
        '''Closes the unified logs reader.'''
        if self._file_object:
            self._file_object.close()
            self._file_object = None

        self._path = None

    def Open(self):
        '''Opens the output writer.

        Returns:
          bool: True if successful or False on error.
        '''
        logger.info('Creating output file %s', self._path)

        try:
            # io.open() is portable between Python 2 and 3
            # using text mode so we don't have to care about end-of-line character
            self._file_object = io.open(self._path, 'wt', encoding='utf-8')
            try:
                if self._mode == 'TSV_ALL':
                    self._file_object.write(self._HEADER_ALL)
                else:
                    self._file_object.write(self._HEADER_DEFAULT)
            except (IOError, OSError):
                logger.exception('Error writing to output file')
                return False
        except (IOError, OSError):
            logger.exception('Failed to open file %s', self._path)
            return False
        return True

    def WriteLogEntries(self, logs):
        '''Writes several Unified Log entries.

        Args:
          logs (???): list of log entries:
        '''
        for log in logs:
            self.WriteLogEntry(log)

    def WriteLogEntry(self, log):
        '''Writes a Unified Log entry.

        Args:
          log (???): log entry:
        '''
        if self._file_object:
            log[3] = UnifiedLogLib.ReadAPFSTime(log[3])

            try:
                if self._mode == 'TSV_ALL':
                    log[18] = '{0!s}'.format(log[18]).upper()
                    log[19] = '{0!s}'.format(log[19]).upper()

                    self._file_object.write((
                        '{}\t0x{:X}\t{}\t{}\t0x{:X}\t{}\t0x{:X}\t0x{:X}\t{}\t'
                        '{}\t{}\t({})\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t'
                        '{}').format(
                            log[0], log[1], log[2], log[3], log[4], log[5],
                            log[6], log[7], log[8], log[9], log[10], log[11],
                            log[12], log[13], log[14], log[15], log[16],
                            log[17], log[18], log[19], log[20], log[21],
                            log[22]))

                else:
                    signpost = ''  # (log[15] + ':') if log[15] else ''
                    if log[15]:
                        signpost += '[' + log[16] + ']'
                    msg = (signpost + ' ') if signpost else ''
                    msg += log[11] + ' ' + (( '(' + log[12] + ') ') if log[12] else '')
                    if len(log[13]) or len(log[14]):
                        msg += '[' + log[13] + ':' + log[14] + '] '
                    msg += log[22]

                    self._file_object.write((
                        '{time:26} {li[4]:<#10x} {li[5]:11} {li[6]:<#20x} '
                        '{li[8]:<6} {li[10]:<4} {message}').format(
                            li=log, time=log[3], message=msg))

            except (IOError, OSError):
                logger.exception('Error writing to output file')


class UnifiedLogReader(object):
    '''Unified log reader.'''

    def __init__(self):
        '''Initializes an unified log reader.'''
        super(UnifiedLogReader, self).__init__()
        self._caches = None
        self._ts_list = []
        self._uuidtext_folder_path = None
        self._vfs = virtual_file_system.VirtualFileSystem(
            virtual_file.VirtualFile)
        self.total_logs_processed = 0

    # TODO: remove log_list_process_func callback from TraceV3.Parse() 
    def _ProcessLogsList(self, logs, tracev3):
        if isinstance(self._output_writer, SQLiteDatabaseOutputWriter):
            self._output_writer.WriteLogEntries(logs)
            self.total_logs_processed += len(logs)
        else:
            for log_entry in logs:
                self._output_writer.WriteLogEntry(log_entry)
                self.total_logs_processed += 1

    def _ReadTraceV3File(self, tracev3_path, output_writer):
        '''Reads a tracev3 file.

        Args:
          tracev3_path (str): path of the tracev3 file.
          output_writer (OutputWriter): output writer.

        Returns:
          TraceV3: tracev3 file.
        '''
        file_object = virtual_file.VirtualFile(tracev3_path, 'traceV3')
        trace_file = tracev3_file.TraceV3(
            self._vfs, file_object, self._ts_list, self._uuidtext_folder_path,
            self._caches)

        # TODO: remove log_list_process_func callback from TraceV3.Parse() 
        self._output_writer = output_writer
        trace_file.Parse(log_list_process_func=self._ProcessLogsList)

    def _ReadTraceV3Folder(self, tracev3_path, output_writer):
        '''Reads all the tracev3 files in the folder.

        Args:
          tracev3_path (str): path of the tracev3 folder.
          output_writer (OutputWriter): output writer.
        '''
        for directory_entry in os.listdir(tracev3_path):
            directory_entry_path = os.path.join(tracev3_path, directory_entry)
            if os.path.isdir(directory_entry_path):
                self._ReadTraceV3Folder(directory_entry_path, output_writer)

            elif (directory_entry.lower().endswith('.tracev3') and
                  not directory_entry.startswith('._')):
                if os.path.getsize(directory_entry_path) > 0:
                    logger.info("Trying to read file - %s", directory_entry_path)
                    self._ReadTraceV3File(directory_entry_path, output_writer)
                else:
                    logger.info("Skipping empty file - %s", directory_entry_path)

    def ReadDscFiles(self, uuidtext_folder_path):
        '''Reads the dsc files.

        Args:
          uuidtext_folder_path (str): path of the uuidtext folder.
        '''
        self._caches = UnifiedLogLib.CachedFiles(self._vfs)
        self._uuidtext_folder_path = uuidtext_folder_path

        self._caches.ParseFolder(self._uuidtext_folder_path)

    def ReadTimesyncFolder(self, timesync_folder_path):
        '''Reads the timesync folder.

        Args:
          timesync_folder_path (str): path of the timesync folder.

        Returns:
          bool: True if successful or False otherwise.
        '''
        self._ts_list = []

        UnifiedLogLib.ReadTimesyncFolder(
            timesync_folder_path, self._ts_list, self._vfs)

        return bool(self._ts_list)

    def ReadTraceV3Files(self, tracev3_path, output_writer):
        '''Reads the tracev3 files.

        Args:
          tracev3_path (str): path of the tracev3 file or folder.
          output_writer (OutputWriter): output writer.
        '''
        if os.path.isdir(tracev3_path):
            self._ReadTraceV3Folder(tracev3_path, output_writer)
        else:
            self._ReadTraceV3File(tracev3_path, output_writer)


def DecompressTraceV3Log(input_path, output_path):
    try:
        with open(input_path, 'rb') as trace_file:
            with open(output_path, 'wb') as out_file:
                return UnifiedLogLib.DecompressTraceV3(trace_file, out_file)
    except:
        logger.exception('')


def Main():
    '''The main program function.

    Returns:
      bool: True if successful or False if not.
    '''
    description = (
        'UnifiedLogReader is a tool to read macOS Unified Logging tracev3 files.\n'
        'This is version {0:s} tested on macOS 10.12.5 - 10.15 and iOS 12.\n\n'
        'Notes:\n-----\n'
        'If you have a .logarchive, then point uuidtext_path to the .logarchive folder, \n'
        'the timesync folder is within the logarchive folder').format(UnifiedLog.__version__)

    arg_parser = argparse.ArgumentParser(
        description=description, formatter_class=argparse.RawTextHelpFormatter)
    arg_parser.add_argument('uuidtext_path', help='Path to uuidtext folder (/var/db/uuidtext)')
    arg_parser.add_argument('timesync_path', help='Path to timesync folder (/var/db/diagnostics/timesync)')
    arg_parser.add_argument('tracev3_path', help='Path to either tracev3 file or folder to recurse (/var/db/diagnostics)')
    arg_parser.add_argument('output_path', help='An existing folder where output will be saved')

    arg_parser.add_argument(
         '-f', '--output_format', action='store', choices=(
             'SQLITE', 'TSV_ALL', 'LOG_DEFAULT'),
         metavar='FORMAT', default='LOG_DEFAULT', help=(
             'Output format: SQLITE, TSV_ALL, LOG_DEFAULT  (Default is LOG_DEFAULT)'), type=str.upper)

    arg_parser.add_argument('-l', '--log_level', help='Log levels: INFO, DEBUG, WARNING, ERROR (Default is INFO)')

    args = arg_parser.parse_args()

    output_path = args.output_path.rstrip('\\/')
    uuidtext_folder_path = args.uuidtext_path.rstrip('\\/')
    timesync_folder_path = args.timesync_path.rstrip('\\/')
    tracev3_path = args.tracev3_path.rstrip('\\/')

    if not os.path.exists(uuidtext_folder_path):
        print('Exiting..UUIDTEXT Path not found {}'.format(uuidtext_folder_path))
        return

    if not os.path.exists(timesync_folder_path):
        print('Exiting..TIMESYNC Path not found {}'.format(timesync_folder_path))
        return

    if not os.path.exists(tracev3_path):
        print('Exiting..traceV3 Path not found {}'.format(tracev3_path))
        return

    if not os.path.exists(output_path):
        print ('Creating output folder {}'.format(output_path))
        os.makedirs(output_path)

    log_file_path = os.path.join(output_path, "Log." + time.strftime("%Y%m%d-%H%M%S") + ".txt")

    # log
    if args.log_level:
        args.log_level = args.log_level.upper()
        if not args.log_level in ['INFO','DEBUG','WARNING','ERROR','CRITICAL']:
            print("Invalid input type for log level. Valid values are INFO, DEBUG, WARNING, ERROR")
            return
        else:
            if args.log_level == "INFO": args.log_level = logging.INFO
            elif args.log_level == "DEBUG": args.log_level = logging.DEBUG
            elif args.log_level == "WARNING": args.log_level = logging.WARNING
            elif args.log_level == "ERROR": args.log_level = logging.ERROR
            elif args.log_level == "CRITICAL": args.log_level = logging.CRITICAL
    else:
        args.log_level = logging.INFO

    log_level = args.log_level #logging.DEBUG
    log_console_handler = logging.StreamHandler()
    log_console_handler.setLevel(log_level)
    log_console_format  = logging.Formatter('%(levelname)s - %(message)s')
    log_console_handler.setFormatter(log_console_format)
    logger.addHandler(log_console_handler)

    #log file
    log_file_handler = logging.FileHandler(log_file_path)
    log_file_handler.setFormatter(log_console_format)
    logger.addHandler(log_file_handler)
    logger.setLevel(log_level)

    unified_log_reader = UnifiedLogReader()

    if not unified_log_reader.ReadTimesyncFolder(timesync_folder_path):
        logger.error('Failed to get any timesync entries')
        return False

    if args.output_format == 'SQLITE':
        database_path = os.path.join(output_path, 'unifiedlogs.sqlite')
        output_writer = SQLiteDatabaseOutputWriter(database_path)

    elif args.output_format in ('TSV_ALL', 'LOG_DEFAULT'):
        file_path = os.path.join(output_path, 'logs.txt')
        output_writer = FileOutputWriter(
            file_path, mode=args.output_format)

    if not output_writer.Open():
        return False

    time_processing_started = time.time()
    logger.info('Started processing')

    unified_log_reader.ReadDscFiles(uuidtext_folder_path)
    unified_log_reader.ReadTraceV3Files(tracev3_path, output_writer)

    output_writer.Close()

    time_processing_ended = time.time()
    run_time = time_processing_ended - time_processing_started
    logger.info("Finished in time = {}".format(time.strftime('%H:%M:%S', time.gmtime(run_time))))
    logger.info("{} Logs processed".format(unified_log_reader.total_logs_processed))
    logger.info("Review the Log file and report any ERRORs or EXCEPTIONS to the developers")

    return True


if __name__ == "__main__":
    if not Main():
        sys.exit(1)
    else:
        sys.exit(0)
