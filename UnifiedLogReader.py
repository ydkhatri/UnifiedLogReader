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
import codecs
import logging
import os
import sys
import time
import UnifiedLogLib

log = logging.getLogger('UNIFIED_LOG_READER')
UnifiedLogLib.log = log
######

f = None
vfs = UnifiedLogLib.VirtualFileSystem(UnifiedLogLib.VirtualFile)
total_logs_processed = 0

def DecompressTraceV3Log(input_path, output_path):
    try:
        with open(input_path, 'rb') as trace_file:
            with open(output_path, 'wb') as out_file:
                return UnifiedLogLib.DecompressTraceV3(trace_file, out_file)
    except:
        log.exception('')

def ProcessLogsList_All(logs, tracev3):
    '''
    Function to process a list of log items.
    logs format = [ source_file, log_file_pos, 
                    continuous_time, time, thread, log_type, 
                    activity_id, parent_activity_id, 
                    pid, ttl, p_name, lib, sub_system, category,
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
                li[8],li[9],li[10],li[11],li[12],li[13],
                li[14],li[15],
                li[16],unicode(li[17]).upper(),unicode(li[18]).upper(),
                li[19],li[20],
                li[21]))
            total_logs_processed += 1
        except:
            log.exception('Error writing to output file')

def ProcessLogsList_DefaultFormat(logs, tracev3):
    global f
    global total_logs_processed
    for li in logs:
        try:
            signpost = '' #(li[14] + ':') if li[14] else ''
            if li[15]:
                signpost += '[' + li[15] + ']'
            msg = (signpost + ' ') if signpost else ''
            msg += li[10] + ' ' + (( '(' + li[11] + ') ') if li[11] else '')
            if len(li[12]) or len (li[13]):
                msg += '[' + li[12] + ':' + li[13] + '] '
            msg += li[21]
            f.write(u'{time:26} {li[4]:<#10x} {li[5]:11} {li[6]:<#20x} {li[8]:<6} {li[9]:<4} {message}\r\n'.format(li=li, time=str(UnifiedLogLib.ReadAPFSTime(li[3])), message=msg))
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
            log.debug("Found file - " + input_file_path)
            UnifiedLogLib.TraceV3(vfs, UnifiedLogLib.VirtualFile(input_file_path, 'traceV3'), ts_list, uuidtext_folder_path, caches).Parse(proc_func)
        elif os.path.isdir(input_file_path):
            RecurseProcessLogFiles(input_file_path, ts_list, uuidtext_folder_path, caches, proc_func)

def main():
    global f
    global vfs
    global total_logs_processed
    recurse = False
    
    if len(sys.argv) < 5:
        print('Only {} arguments given'.format(len(sys.argv)))
        print('Usage: tool.py output_path uuid_folder_path timesync_folder_path [-r] traceV3_file_path')
        print('       If using -r, specify a folder instead of a file to recurse and find all .traceV3 files')
        sys.exit(1)

    output_path = sys.argv[1].rstrip('\\')
    uuidtext_folder_path = sys.argv[2].rstrip('\\')
    timesync_folder_path = sys.argv[3].rstrip('\\')
    if sys.argv[4].lower() == '-r': #folder to recurse follows
        recurse = True
        traceV3_path = sys.argv[5].rstrip('\\')
    else:
        traceV3_path = sys.argv[4].rstrip('\\')
    if not os.path.exists(uuidtext_folder_path):
        print('Exiting..UUIDTEXT Path not found {}'.format(uuidtext_folder_path))
        return
    if not os.path.exists(timesync_folder_path):
        print('Exiting..TIMESYNC Path not found {}'.format(timesync_folder_path))
        return
    if not os.path.exists(traceV3_path):
        print('Exiting..traceV3 Path not found {}'.format(traceV3_path))
        return   
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    log_file_path = os.path.join(output_path, "Log." + unicode(time.strftime("%Y%m%d-%H%M%S")) + ".txt")

    # log
    log_level = logging.DEBUG
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

    mode = 'def' #'all' 

    ts_list = []
    UnifiedLogLib.ReadTimesyncFolder(timesync_folder_path, ts_list, vfs)
    if ts_list:
        try:
            f = codecs.open(os.path.join(output_path, 'logs.txt'), 'wb', 'utf-8')
            if mode == 'all':
                f.write('SourceFile\tLogFilePos\tContinousTime\tTime\tThreadId\tLogType\tActivityId\tParentActivityId\t' +
                        'PID\tTTL\tProcessName\tSenderName\tSubsystem\tCategory\t' +
                        'SignpostName\tSignpostString\t' + 
                        'ImageOffset\tImageUUID\tProcessImageUUID\t' +
                        'SenderImagePath\tProcessImagePath\t' +
                        'LogMessage\r\n')
                proc_func = ProcessLogsList_All
            else:
                default_format_header = 'Timestamp                  Thread     Type        Activity             PID    TTL  Message\r\n'
                f.write(default_format_header)
                proc_func = ProcessLogsList_DefaultFormat
        except:
            log.error("Failed to open file for writing")
            f = None
        if f:
            time_processing_started = time.time()

            #Read uuidtext & dsc files
            caches = UnifiedLogLib.CachedFiles(vfs)
            caches.ParseFolder(uuidtext_folder_path)
            log.debug('DSC count = {}'.format(len(caches.cached_dsc)))
            
            #Read .traceV3 files
            if recurse:
                RecurseProcessLogFiles(traceV3_path, ts_list, uuidtext_folder_path, caches, proc_func)
            else:
                UnifiedLogLib.TraceV3(vfs, UnifiedLogLib.VirtualFile(traceV3_path, 'traceV3'), ts_list, uuidtext_folder_path, caches).Parse(proc_func)
            f.close()
            
            time_processing_ended = time.time()
            run_time = time_processing_ended - time_processing_started
            log.info("Finished in time = {}".format(time.strftime('%H:%M:%S', time.gmtime(run_time))))
            log.info("{} Logs processed".format(total_logs_processed))
            log.info("Review the Log file and report any ERRORs or EXCEPTIONS to the developers")
    else:
        log.error('Failed to get any timesync entries')

if __name__ == "__main__":
    main()
