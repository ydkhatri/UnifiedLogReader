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
# Last Updated : 2019-01-23
# Purpose/Usage: This script will read unified logs. Tested on python2.7
# 
# Notes: 
# Currently this is tested on version 17(0x11) of the tracev3 file used in 
# macOS Sierra (10.12.5) and above (including Mojave 10.14.2). It will not
# work on Sierra (10.12) as it uses version 14(0xE), a later update will
# address this.
#

from __future__ import print_function
#from __future__ import unicode_literals
import argparse
import codecs
import logging
import os
import sqlite3
import sys
import time

from UnifiedLog import Lib as UnifiedLogLib


log = logging.getLogger('UNIFIED_LOG_READER')
UnifiedLogLib.log = log
######

f = None
vfs = UnifiedLogLib.VirtualFileSystem(UnifiedLogLib.VirtualFile)
total_logs_processed = 0
db_conn = None

def DecompressTraceV3Log(input_path, output_path):
    try:
        with open(input_path, 'rb') as trace_file:
            with open(output_path, 'wb') as out_file:
                return UnifiedLogLib.DecompressTraceV3(trace_file, out_file)
    except:
        log.exception('')

def InitializeDatabase(path):
    global db_conn
    try:
        if os.path.exists(path):
            log.info('Database file already exists, trying to delete it')
            os.remove(path)
        log.info('Trying to create new database file at ' + path)
        db_conn = sqlite3.connect(path)
        return True
    except:
        log.exception('Failed to create database at ' + path)
    return False

def CreateTable(conn):
    try:
        create_statement = 'CREATE TABLE logs ('\
                    'SourceFile TEXT, SourceFilePos INTEGER, ContinuousTime TEXT, TimeUtc TEXT, Thread INTEGER, Type TEXT, '\
                    'ActivityID INTEGER, ParentActivityID INTEGER, ProcessID INTEGER, EffectiveUID INTEGER, TTL INTEGER, '\
                    'ProcessName TEXT, SenderName TEXT, Subsystem TEXT, Category TEXT, SignpostName TEXT, SignpostInfo TEXT, '\
                    'ImageOffset INTEGER, SenderUUID TEXT, ProcessImageUUID TEXT, SenderImagePath TEXT, '\
                    'ProcessImagePath TEXT, Message TEXT'\
                    ')'
        cursor = conn.cursor()
        cursor.execute(create_statement)
        return True
    except:
        log.exception('Exception while creating Table in database')
    return False

def CloseDB():
    try:
        if db_conn:
            db_conn.close()
    except:
        pass

def ProcessLogsList_Sqlite(logs, tracev3):
    global db_conn
    global total_logs_processed

    if db_conn == None:
        return
    cursor = db_conn.cursor()
    query = 'INSERT INTO logs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
    try:
        for li in logs:
            li[3] = UnifiedLogLib.ReadAPFSTime(li[3])
            li[18] = unicode(li[18])
            li[19] = unicode(li[19])
        cursor.executemany(query, logs)
        db_conn.commit()
        cursor.close()
        total_logs_processed += len(logs)
    except:
        log.exception('Error inserting data into database')    

def ProcessLogsList_All(logs, tracev3):
    '''
    Function to process a list of log items.
    logs format = [ source_file, log_file_pos, 
                    continuous_time, time, thread, log_type, 
                    activity_id, parent_activity_id, 
                    pid, euid, ttl, p_name, lib, sub_system, category,
                    signpost_name, signpost_string, 
                    image_offset, image_UUID, process_image_UUID, 
                    sender_image_path, process_image_path,
                    log_msg
                  ]
    '''
    global f
    global total_logs_processed
    for li in logs:
        try:
            f.write(u'{}\t0x{:X}\t'\
                '{}\t{}\t0x{:X}\t{}\t'\
                '0x{:X}\t0x{:X}\t'\
                '{}\t{}\t{}\t({})\t{}\t{}\t'\
                '{}\t{}\t'\
                '{}\t{}\t{}\t'\
                '{}\t{}\t'\
                '{}'\
                '\r\n'.format(\
                li[0],li[1],
                li[2],UnifiedLogLib.ReadAPFSTime(li[3]),li[4],li[5],
                li[6],li[7],
                li[8],li[9],li[10],li[11],li[12],li[13],li[14],
                li[15],li[16],
                li[17],unicode(li[18]).upper(),unicode(li[19]).upper(),
                li[20],li[21],
                li[22]))
            total_logs_processed += 1
        except:
            log.exception('Error writing to output file')

def ProcessLogsList_DefaultFormat(logs, tracev3):
    global f
    global total_logs_processed
    for li in logs:
        try:
            signpost = '' #(li[15] + ':') if li[15] else ''
            if li[15]:
                signpost += '[' + li[16] + ']'
            msg = (signpost + ' ') if signpost else ''
            msg += li[11] + ' ' + (( '(' + li[12] + ') ') if li[12] else '')
            if len(li[13]) or len (li[14]):
                msg += '[' + li[13] + ':' + li[14] + '] '
            msg += li[22]
            f.write(u'{time:26} {li[4]:<#10x} {li[5]:11} {li[6]:<#20x} {li[8]:<6} {li[10]:<4} {message}\r\n'.format(li=li, time=str(UnifiedLogLib.ReadAPFSTime(li[3])), message=msg))
            total_logs_processed += 1
        except:
            log.exception('Error writing to output file')

def RecurseProcessLogFiles(input_path, ts_list, uuidtext_folder_path, caches, proc_func):
    '''Recurse the folder located by input_path and process all .traceV3 files'''
    global vfs
    files = os.listdir(input_path)
    
    for file_name in files:
        input_file_path = os.path.join(input_path, file_name)
        if file_name.lower().endswith('.tracev3') and not file_name.startswith('._'):
            log.info("Trying to read file - " + input_file_path)
            UnifiedLogLib.TraceV3(vfs, UnifiedLogLib.VirtualFile(input_file_path, 'traceV3'), ts_list, uuidtext_folder_path, caches).Parse(proc_func)
        elif os.path.isdir(input_file_path):
            RecurseProcessLogFiles(input_file_path, ts_list, uuidtext_folder_path, caches, proc_func)

def main():
    global f
    global vfs
    global total_logs_processed
    global db_conn
    recurse = False

    arg_parser = argparse.ArgumentParser(description='UnifiedLogReader is a tool to read macOS Unified Logging tracev3 files.\r\n'\
                                            'This is version 1.0 tested on macOS 10.12.5 - 10.14.3.\n\nNotes:\n-----\n'\
                                            'If you have a .logarchive, then point uuidtext_path to the .logarchive folder,\n'\
                                            ' the timesync folder is within the logarchive folder', 
                                            formatter_class=argparse.RawTextHelpFormatter)
    arg_parser.add_argument('uuidtext_path', help='Path to uuidtext folder (/var/db/uuidtext)')
    arg_parser.add_argument('timesync_path', help='Path to timesync folder (/var/db/diagnostics/timesync)')
    arg_parser.add_argument('tracev3_path', help='Path to either tracev3 file or folder to recurse (/var/db/diagnostics)')
    arg_parser.add_argument('output_path', help='An existing folder where output will be saved')

    arg_parser.add_argument('-f', '--output_format', help='SQLITE, TSV_ALL, TSV_DEFAULT  (Default is TSV_DEFAULT)')
    arg_parser.add_argument('-l', '--log_level', help='Log levels: INFO, DEBUG, WARNING, ERROR (Default is INFO)')

    args = arg_parser.parse_args()

    output_path = args.output_path.rstrip('\\/')
    uuidtext_folder_path = args.uuidtext_path.rstrip('\\/')
    timesync_folder_path = args.timesync_path.rstrip('\\/')
    tracev3_path = args.tracev3_path.rstrip('\\/')
    if os.path.isdir(tracev3_path):
        recurse = True

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
    
    # output format
    if args.output_format:
        args.output_format = args.output_format.upper()
        if not args.output_format in ['SQLITE','TSV_DEFAULT','TSV_ALL']:
            print("Invalid input type for output format. Valid values are SQLITE, TSV_ALL, TSV_DEFAULT")
            return
    else:
        args.output_format = 'TSV_DEFAULT'

    log_file_path = os.path.join(output_path, "Log." + unicode(time.strftime("%Y%m%d-%H%M%S")) + ".txt")

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
    log.addHandler(log_console_handler)

    #log file
    log_file_handler = logging.FileHandler(log_file_path)
    log_file_handler.setFormatter(log_console_format)
    log.addHandler(log_file_handler)
    log.setLevel(log_level)

    ts_list = []
    UnifiedLogLib.ReadTimesyncFolder(timesync_folder_path, ts_list, vfs)
    if ts_list:
        try:
            if args.output_format == 'SQLITE':
                if InitializeDatabase(os.path.join(output_path, 'unifiedlogs.sqlite')) and CreateTable(db_conn):
                    proc_func = ProcessLogsList_Sqlite
                else:
                    return
            else:
                log.info('Creating output file {}'.format(os.path.join(output_path, 'logs.txt')))
                f = codecs.open(os.path.join(output_path, 'logs.txt'), 'wb', 'utf-8')
                if args.output_format == 'TSV_ALL':
                    f.write('SourceFile\tLogFilePos\tContinousTime\tTime\tThreadId\tLogType\tActivityId\tParentActivityId\t' +
                            'PID\tEUID\tTTL\tProcessName\tSenderName\tSubsystem\tCategory\t' +
                            'SignpostName\tSignpostString\t' + 
                            'ImageOffset\tImageUUID\tProcessImageUUID\t' +
                            'SenderImagePath\tProcessImagePath\t' +
                            'LogMessage\r\n')
                    proc_func = ProcessLogsList_All
                else: # 'TSV_DEFAULT'
                    default_format_header = 'Timestamp                  Thread     Type        Activity             PID    TTL  Message\r\n'
                    f.write(default_format_header)
                    proc_func = ProcessLogsList_DefaultFormat
        except:
            log.exception("Failed to open file for writing")
            return

        time_processing_started = time.time()
        log.info('Started processing')

        #Read dsc files into cache
        caches = UnifiedLogLib.CachedFiles(vfs)
        caches.ParseFolder(uuidtext_folder_path)

        #Read .traceV3 files
        if recurse:
            RecurseProcessLogFiles(tracev3_path, ts_list, uuidtext_folder_path, caches, proc_func)
        else:
            UnifiedLogLib.TraceV3(vfs, UnifiedLogLib.VirtualFile(tracev3_path, 'traceV3'), ts_list, uuidtext_folder_path, caches).Parse(proc_func)
        if f:
            f.close()
        if db_conn:
            CloseDB()
        
        time_processing_ended = time.time()
        run_time = time_processing_ended - time_processing_started
        log.info("Finished in time = {}".format(time.strftime('%H:%M:%S', time.gmtime(run_time))))
        log.info("{} Logs processed".format(total_logs_processed))
        log.info("Review the Log file and report any ERRORs or EXCEPTIONS to the developers")
    else:
        log.error('Failed to get any timesync entries')

if __name__ == "__main__":
    main()
