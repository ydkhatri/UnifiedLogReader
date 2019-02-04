# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Unified log reader library
# Script Name   : UnifiedLogLib.py
# Author        : Yogesh Khatri
# Last Updated  : 2019-01-18
# Purpose/Usage : This library will read unified logs (.traceV3 files)
# Notes         : Needs python2 (not python3 ready yet!)
#
# Currently this is tested on version 17(0x11) of the tracev3 file used in 
# macOS Sierra (10.12.5) and above (including Mojave 10.14.2). It will not
# work on Sierra (10.12) as it uses version 14(0xE), a later update will
# address this.
#
# MIT License
#
# Copyright (c) 2019 Yogesh Khatri (@swiftforensics)
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

from __future__ import print_function
from __future__ import unicode_literals

import binascii
import datetime
import ipaddress
import logging
import os
import re
import struct
import time

from uuid import UUID

import biplist
import lz4.block


log = logging.getLogger('UNIFIED_LOG_READER_LIB')

# FORMAT
#  Timestamp  Thread  Type  Activity  PID  PROC_NAME: (Library) [Subsystem:Category]  MESSAGE

# Timesync in-memory and persist start values not found in Tracev3

class VirtualFile(object):
    '''
        This is a virtual file object. Its purpose is to enable the same parsing code to be used
        regardless of whether your file is local or in-memory or remote accessed via your custom
        API. This base implementation operates on local files. You can inherit and override these
        functions to implement accessing files or other data stores.
    '''
    def __init__(self, path, filetype=''):
        self.path = path
        self.filename = os.path.basename(path)
        self.file_type = filetype
        self.file_pointer = None # This will be set to file or file-like object on successful open
        self.is_valid = True     # Set for corrupted or missing files
        self.file_not_found = False

    def open(self, mode='rb'):
        '''Opens a file for reading/writing, returns file pointer or None'''
        try:
            log.debug('Trying to read {} file {}'.format(self.file_type, self.path))
            self.file_pointer = open(self.path, mode)
            return self.file_pointer
        except Exception as ex:
            if str(ex).find('No such file') == -1:
                log.exception('Failed to open file {}'.format(self.path))
            else:
                log.error('Failed to open as file not found {}'.format(self.path))
                self.file_not_found = True
            self.is_valid = False
        return None

    def get_file_size(self):
        '''Returns file logical size. Must be called after file is opened'''
        if not self.file_pointer:
            raise ValueError('File pointer was invalid. File must be opened before calling get_file_size()')
        original_pos = self.file_pointer.tell()
        self.file_pointer.seek(0, 2) # seek to end
        size = self.file_pointer.tell()
        self.file_pointer.seek(original_pos)
        return size

    def close(self):
        if self.file_pointer:
            self.file_pointer.close()

class VirtualFileSystem(object):
    '''
        This class implements the file system functions that the library relies on.
        In this base class, they default to the local OS ones such as os.path.exits(),
        os.listdir() and a few others. To make them do something else, inherit the 
        class and override its methods.
    '''
    def __init__(self, virtual_file_class):
        self.virtual_file_class = virtual_file_class
    
    def path_exists(self, path):
        '''Return True if file/folder specified by 'path' exists'''
        return os.path.exists(path)
    
    def listdir(self, path):
        '''Return a list of all files/folders contained at given path'''
        return os.listdir(path)

    def is_dir(self, path):
        '''Return True if path is a directory'''
        return os.path.isdir(path)

    def path_join(self, path, *paths):
        '''Return the joined path, similar to os.path.join(path, *paths)'''
        return os.path.join(path, *paths)

    def get_virtual_file(self, path, filetype=''):
        '''Return a VirtualFile object'''
        return self.virtual_file_class(path, filetype)

def ReadAPFSTime(mac_apfs_time): # Mac APFS timestamp is nano second time epoch beginning 1970/1/1
    '''Returns datetime object, or empty string upon error'''
    if mac_apfs_time not in ( 0, None, ''):
        try:
            if type(mac_apfs_time) in (str, unicode):
                mac_apfs_time = float(mac_apfs_time)
            return datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=mac_apfs_time/1000000000.)
        except Exception as ex:
            log.error("ReadAPFSTime() Failed to convert timestamp from value " + str(mac_apfs_time) + " Error was: " + str(ex))
    return ''

def ReadNtSid(data):
    '''Reads a windows SID from its raw binary form'''
    sid = ''
    size = len(data)
    if size < 8:
        log.error('Not a windows sid')
    rev = struct.unpack("<B", data[0])[0]
    num_sub_auth = struct.unpack("<B", data[1])[0]
    authority = struct.unpack(">I", data[4:8])[0]

    if size < (8 + (num_sub_auth * 4)):
        log.error('buffer too small or truncated - cant fit all sub_auth')
        return ''
    sub_authorities = struct.unpack('<{}I'.format(num_sub_auth), data[8:8*num_sub_auth])
    sid = 'S-{}-{}-'.format(rev, authority) + '-'.join([str(sa) for sa in sub_authorities])
    return sid

def Read_CLClientManagerStateTrackerState(data):
    ''' size=0x8 int, bool '''
    locationServicesEnabledStatus, locationRestricted = struct.unpack('<ii', data[0:8])
    return str( {"locationServicesEnabledStatus":locationServicesEnabledStatus, "locationRestricted":True if locationRestricted else False} )

# _CLLocationManagerStateTrackerState
# https://github.com/nst/iOS-Runtime-Headers/blob/fbb634c78269b0169efdead80955ba64eaaa2f21/Frameworks/CoreLocation.framework/CLLocationManagerStateTracker.h

#def Read_CLDaemonStatusStateTrackerState(data):
    ''' size=0x28 
        From classdump of locationd.nsxpc from:
        https://gist.github.com/razvand/578f94748b624f4d47c1533f5a02b095
        struct Battery {
            double level;
            _Bool charged;
            _Bool connected;
            int chargerType;
            _Bool wasConnected;
        };
        struct _CLDaemonStatusStateTrackerState {
            struct Battery batteryData;
            int reachability;
            int thermalLevel;
            _Bool airplaneMode;
            _Bool batterySaverModeEnabled;
            _Bool pushServiceConnected;
            _Bool restrictedMode;
        };
        Not sure how this is 0x28 bytes!
        Sample output:
        {"restrictedMode":false,
        "pushServiceConnected":false,
            "batteryData":{"wasConnected":false,"charged":false,"level":-1,"connected":false,"chargerType":"kChargerTypeUnknown"},
         "thermalLevel":-1,
         "batterySaverModeEnabled":false,
         "reachability":"kReachabilityLarge",
         "airplaneMode":false}

    '''
    # 
    #pass


def ReadCString(data, max_len=1024):
    '''Returns a C utf8 string (excluding terminating null)'''
    pos = 0
    max_len = min(len(data), max_len)
    string = ''
    try:
        null_pos = data.find(b'\x00', 0, max_len)
        if null_pos == -1:
            log.warning("Possible corrupted string encountered")
            string = data.decode('utf8')
        else:
            string = data[0:null_pos].decode('utf8')
    except:
        log.exception('Error reading C-String')
    return string

def ReadCStringAndEndPos(data, max_len=1024):
    '''Returns a tuple containing a C utf8 string (excluding terminating null)
       and the end position in the data
       ("utf8-string", pos)
    '''
    pos = 0
    max_len = min(len(data), max_len)
    string = ''
    null_pos = -1
    try:
        null_pos = data.find(b'\x00', 0, max_len)
        if null_pos == -1:
            log.warning("Possible corrupted string encountered")
            string = data.decode('utf8')
        else:
            string = data[0:null_pos].decode('utf8')
    except:
        log.exception('Error reading C-String')
    return string, null_pos

def DecompressTraceV3(trace_file, out_file):
    ''' Creates an uncompressed version of the .traceV3 file.
        Input parameters:
        trace_file = file pointer to .traceV3 file (opened as 'rb')
        out_file   = file pointer to blank file (opened as 'wb')
        Returns True/False
    '''
    try:
        index = 0
        tag = trace_file.read(4)
        while tag:
            begin_pos = trace_file.tell() - 4
            trace_file.seek(begin_pos + 8)
            struct_len = struct.unpack('<Q', trace_file.read(8))[0]
            log.debug("index={} pos=0x{:X} tag=0x{}".format(index, begin_pos, binascii.hexlify(tag)[::-1]))

            trace_file.seek(begin_pos)
            chunk_data_incl_header = trace_file.read(16 + struct_len)
            if tag == b'\x00\x10\x00\x00': # header
                out_file.write(chunk_data_incl_header) # boot_uuid header, write to output directly
            elif tag[0] == b'\x0B':
                out_file.write(chunk_data_incl_header) # uncompressed, write to output directly
            elif tag[0] == b'\x0D':
                uncompressed = DecompressChunkData(chunk_data_incl_header[16:], struct_len)
                out_file.write(chunk_data_incl_header[0:8]) # Same Header !
                out_file.write(struct.pack('<Q', len(uncompressed))) # New size
                out_file.write(uncompressed)
            else:
                log.error('Unknown chunk tag value encountered : {}'.format(binascii.hexlify(tag)))
                out_file.write(chunk_data_incl_header)
            if struct_len % 8: # Go to QWORD boundary
                struct_len += 8 - (struct_len % 8)
            if out_file.tell() % 8: # Go to QWORD boundary on output
                out_file.write(b'\x00\x00\x00\x00\x00\x00\x00'[0:(8-out_file.tell() % 8)])
            trace_file.seek(begin_pos + 16 + struct_len)
            tag = trace_file.read(4)
            index += 1
    except Exception as ex:
        log.exception('')
        return False
    return True

def DecompressChunkData(chunk_data, data_len):
    '''Decompress an individual compressed chunk (tag=0x600D)'''
    uncompressed = b''
    if chunk_data[0:4] in [b'bv41', b'bv4-']:
        last_uncompressed = b''
        comp_start = 0 # bv** offset
        comp_header = chunk_data[comp_start:comp_start + 4]
        while (data_len > comp_start) and (comp_header != b'bv4$'):
            if comp_header == b'bv41':
                uncompressed_size, compressed_size = struct.unpack('<II', chunk_data[comp_start + 4:comp_start + 12])
                last_uncompressed = lz4.block.decompress(chunk_data[comp_start + 12: comp_start + 12 + compressed_size], uncompressed_size, dict=last_uncompressed)
                comp_start += 12 + compressed_size
                uncompressed += last_uncompressed
            elif comp_header == b'bv4-':
                uncompressed_size = struct.unpack('<I', chunk_data[comp_start + 4:comp_start + 8])[0]
                uncompressed += chunk_data[comp_start + 8:comp_start + 8 + uncompressed_size]
                comp_start += 8 + uncompressed_size
            else:
                log.error('Unknown compression value {} @ 0x{:X} - {}'.format(binascii.hexlify(comp_header), begin_pos + comp_start, comp_header))
                break
            comp_header = chunk_data[comp_start:comp_start + 4]
    else:
        log.error('Unknown compression type {}'.format(binascii.hexlify(chunk_data[16:20])))
    return uncompressed

class ExtraFileReference:
    '''Extra file reference object. Some ProcInfos have messages in more than one uuidtext file'''
    def __init__(self, data_size, uuid_file_index, u2, v_offset, id):
        self.data_size = data_size # data size
        self.uuid_file_index = uuid_file_index
        self.unknown2 = u2
        self.v_offset = v_offset # virtual offset
        self.id = id

class ProcInfo:
    def __init__(self, id, flags, uuid_file_index, dsc_file_index, proc_id1, proc_id2, pid, euid, u6, num_extra_uuid_refs, u8, num_subsys_cat_elements, u9, extra_file_refs):
        self.id = id
        self.flags = flags
        self.uuid_file_index = uuid_file_index
        self.dsc_file_index = dsc_file_index
        self.proc_id1 = proc_id1 # usually same as pid (but not always!)
        self.proc_id2 = proc_id2 # secondary pid like unique value for getting unique entries when 2 proc_info have same pid
        self.pid = pid
        self.euid = euid
        self.unk_val6 = u6
        self.num_extra_uuid_refs = num_extra_uuid_refs
        self.unk_val8 = u8
        self.num_subsys_cat_elements = num_subsys_cat_elements
        self.unk_val9 = u9

        self.items = {}    #  key = item_id, val = (subsystem, category)
        self.extra_file_refs = extra_file_refs # In addition to self.uuid_file_index

    def GetSubSystemAndCategory(self, sc_id):
        sc = self.items.get(sc_id, None)
        if sc:
            return (sc[0], sc[1])
        # Not found!
        log.error("Could not find subsystem_category_id={}".format(sc_id))
        return ('','')

class ChunkMeta:
    def __init__(self, continuous_time_first, continuous_time_last,chunk_len, compression_alg):
        self.continuous_time_first = continuous_time_first
        self.continuous_time_last = continuous_time_last
        self.length_of_chunk = chunk_len # Chunk to follow
        self.compression_alg = compression_alg # 0x100 (256) = lz4
        self.ProcInfo_Ids = []
        self.StringIndexes = []
        self.ProcInfos = {}   # key = pid
        self.Strings = {} # key = string offset

class Catalog:
    def __init__(self):
        self.ContinuousTime = 0
        self.FileObjects = []
        self.Strings = ''
        self.ProcInfos = []
        self.ChunkMetaInfo = []

    def GetProcInfoById(self, id):
        for proc_info in self.ProcInfos:
            if proc_info.id == id:
                return proc_info
        # Not found!
        log.error("ProcInfo with id={} not found".format(id))
        return None

class TraceV3():
    def __init__(self, v_fs, v_file, ts_list, uuidtext_folder_path, cached_files=None):
        '''
            Input params:
            v_fs    = VirtualFileSystem object for FS operations (listing dirs, opening files ,..)
            v_file  = VirtualFile object for .traceV3 file
            ts_list = List of TimeSync objects
            uuidtext_folder_path = Path to folder containing Uuidtext folders (and files)
            cached_files = CachedFiles object for dsc & uuidtext files (can be None)
        '''
        self.vfs = v_fs
        self.file = v_file
        # Header info
        #self.header_unknown = 0
        self.header_data_length = 0   # 0xD0 Length of remaining header
        self.header_unknown1 = 0 # 1
        self.header_unknown2 = 0 # 1
        self.header_continuousTime = 0
        self.header_item_continuousTime = 0
        self.header_timestamp = 0 # HFS time 4 bytes
        self.header_unknown5 = 0 # 0
        self.header_unknown6 = 0
        self.header_bias_in_seconds = 0
        self.header_unknown8 = 0
        self.header_unknown9 = 0
        self.ts_list = ts_list
        self.cached_files = cached_files
        self.uuidtext_folder_path = uuidtext_folder_path
        self.dsc_folder_path = v_fs.path_join(uuidtext_folder_path, "dsc")
        self.other_uuidtext = {} # cacheing uuidtext files referenced individually
        self.regex_pattern = r"%(\{[^\}]{1,64}\})?([0-9. *\-+#']{0,6})([hljztLq]{0,2})([@dDiuUxXoOfeEgGcCsSpaAFP])"
        # Regex pattern looks for strings in this format:  % {..} flags width.precision modifier specifier
        #                                                     --   -------------------   ------   ------
        #   Groups                                            g1            g2              g3       g4
        #
        self.regex = re.compile(self.regex_pattern)
        # from header items
        self.system_boot_uuid = None
        self.large_data = {} # key = ( data_ref_id << 64 | contTime ) , value = data 
        self.boot_uuid_ts_list = None
        self.chunk_read_count = 0

    def ParseChunkHeader(self, buffer, debug_file_pos):
        '''Returns tuple (tag, Subtag, DataLength)'''
        tag, subtag, data_length = struct.unpack("<IIQ", buffer)
        log.debug("Chunk {} Tag=0x{:X} Subtag=0x{:X} Data_Length=0x{:X} @ 0x{:X}".format(self.chunk_read_count, tag, subtag, data_length, debug_file_pos))
        self.chunk_read_count += 1
        return (tag, subtag, data_length)

    def ParseFileHeader(self, buffer, data_length):
        self.header_data_length = data_length
        self.header_unknown1, self.header_unknown2, self.header_continuousTime,\
        self.header_timestamp, self.header_unknown5, self.header_unknown6, self.header_bias_in_seconds,\
        self.header_unknown8, self.header_unknown9 = struct.unpack("<IIQiIIiII", buffer[0:40])
        # Read header items (Log configuration?)
        pos = 40
        while pos < data_length:
            item_id, item_length = struct.unpack("<II", buffer[pos:pos+8])
            pos += 8
            if item_id == 0x6100 :  # continuous time
                self.header_item_continuousTime = struct.unpack("<Q", buffer[pos:pos+item_length])[0]
            elif item_id == 0x6101: pass # machine hostname & model
            elif item_id == 0x6102: # uuid
                self.system_boot_uuid = UUID(bytes=buffer[pos:pos+16])
                self.boot_uuid_ts_list = GetBootUuidTimeSyncList(self.ts_list, self.system_boot_uuid)
                if not self.boot_uuid_ts_list:
                    raise ValueError('Could not get Timesync for boot uuid! Cannot parse file..')
            elif item_id == 0x6103: # timezone string
                pass
            else:                   # not yet seen item
                log.info('New header item seen, item_id=0x{:X}'.format(item_id))
            pos += item_length
        self.DebugPrintTimestampFromContTime(self.header_item_continuousTime, "File Header")

    def ProcessReferencedFile(self, uuid_string, catalog):
        '''Find, open and parse a file. Add the file object to catalog.FileObjects list'''
        # Try as dsc file, if missing, try as uuidtext, if missing, then treat as missing uuidtext
        try:
            if self.cached_files:
                dsc = self.cached_files.cached_dsc.get(uuid_string, None) # try as dsc
                if dsc:
                    catalog.FileObjects.append(dsc)
                    return
                else:
                    ut = self.cached_files.cached_uuidtext.get(uuid_string, None)
                    if ut:
                        catalog.FileObjects.append(ut)
                        return
            # Try as Dsc
            full_path = self.vfs.path_join(self.dsc_folder_path, uuid_string)
            if self.vfs.path_exists(full_path):
                dsc = Dsc(self.vfs.get_virtual_file(full_path, 'Dsc'))
                dsc.Parse()
                catalog.FileObjects.append(dsc)
            else:
                # Try as uuidtext
                is_dsc = False
                full_path = self.vfs.path_join(self.uuidtext_folder_path, uuid_string[0:2], uuid_string[2:])
                ut = Uuidtext(self.vfs.get_virtual_file(full_path, 'Uuidtext'), UUID(uuid_string))
                ut.Parse()
                catalog.FileObjects.append(ut)
        except:
            log.exception('')

    def ProcessMetaChunk(self, buffer, debug_file_pos):
        '''Read chunk with flag 0x600B, this contains metadata/catalog data'''
        len_buffer = len(buffer)
        pos = 0
        catalog = Catalog()
        offset_strings, offset_proc_info, num_proc_info_to_follow, offset_chunk_meta, num_chunks_to_follow, \
          self.ContinuousTime = struct.unpack("<HHHHQQ", buffer[0:24])
        pos = 24
        self.DebugPrintTimestampFromContTime(self.ContinuousTime, "Catalog Chunk")
        for i in range(offset_strings/16):
            file_path = binascii.hexlify(buffer[pos:pos+16]).upper()
            self.ProcessReferencedFile(file_path, catalog)
            pos += 16
        pos = offset_strings + 24 # should already be here after reading filesUsed
        catalog.Strings = buffer[pos : pos + offset_proc_info - offset_strings]
        # ProcInfos
        pos = 24 + offset_proc_info
        for i in range(num_proc_info_to_follow):
            id, flags, file_id, dsc_file_index, proc_id1, proc_id2, pid, euid, \
            u6, num_extra_uuid_refs, u8 = struct.unpack("<HHhhQIIIIII", buffer[pos:pos+40])
            pos += 40
            extra_file_refs = []
            if num_extra_uuid_refs:
                # If more than one file is referenced by this proc_info, then this section is present
                for j in range(num_extra_uuid_refs):
                    ref_data_size, ref_u2, uuid_file_index, ref_v_offset, ref_id = struct.unpack('<IIhIh', buffer[pos:pos+16])
                    extra_file_refs.append(ExtraFileReference(ref_data_size, uuid_file_index, ref_u2, ref_v_offset, ref_id))
                    pos += 16
                    # sometimes uuid_file_index is -ve, 0xFF7F (-129)
            num_subsys_cat_elements, u9 = struct.unpack("<II", buffer[pos:pos+8])
            pos += 8
            proc_info = ProcInfo(id, flags, file_id, dsc_file_index, proc_id1, proc_id2, pid, euid, u6, num_extra_uuid_refs, u8, num_subsys_cat_elements, u9, extra_file_refs)
            catalog.ProcInfos.append(proc_info)
            if num_subsys_cat_elements > 0:
                for item_index in range(num_subsys_cat_elements):
                    item_id, subsystem_offset, category_offset = struct.unpack("<HHH", buffer[pos:pos+6])
                    pos += 6
                    proc_info.items[item_id] = ( ReadCString(catalog.Strings[subsystem_offset:]), ReadCString(catalog.Strings[category_offset:]) )
                #padding
                byte_count = num_subsys_cat_elements * 6
                if byte_count < 8:
                    pos += (8 - byte_count)
                elif (byte_count % 8) > 0:
                    pos += 8 - (byte_count % 8)
        #ChunkMeta header
        pos = 24 + offset_chunk_meta
        for i in range(num_chunks_to_follow):
            c_time_first, c_time_last, chunk_len, compression_alg = struct.unpack('<QQII', buffer[pos:pos+24])
            pos += 24
            self.DebugPrintTimestampFromContTime(c_time_first, "ChunkMeta {} CTime First".format(i))
            self.DebugPrintTimestampFromContTime(c_time_last, "ChunkMeta {} CTime Last".format(i))
            chunk_meta = ChunkMeta(c_time_first, c_time_last, chunk_len, compression_alg)
            catalog.ChunkMetaInfo.append(chunk_meta)
            num_proc_info_indexes = struct.unpack('<I', buffer[pos:pos+4])[0]
            pos += 4
            chunk_meta.ProcInfo_Ids = struct.unpack('<{}H'.format(num_proc_info_indexes), buffer[pos:pos + (num_proc_info_indexes*2)])
            pos += num_proc_info_indexes*2
            for proc_info_id in chunk_meta.ProcInfo_Ids:
                # Find it in catalog.ProcInfos and insert ref in chunk_meta.ProcInfos
                #  ref is unique by using both proc_id1 and proc_id2 
                proc_info = catalog.GetProcInfoById(proc_info_id)
                if proc_info:    
                    chunk_meta.ProcInfos[ proc_info.proc_id2 | (proc_info.proc_id1 << 32) ] = proc_info
            num_string_indexes = struct.unpack('<I', buffer[pos:pos+4])[0]
            pos += 4
            chunk_meta.StringIndexes = struct.unpack('<{}H'.format(num_string_indexes), buffer[pos:pos + (num_string_indexes*2)])
            pos += num_string_indexes*2
            #padding
            if (pos % 8) != 0:
                pos += (8 - (pos % 8))
        return catalog

    def ReadLogDataBuffer2(self, buffer, buf_size, strings_buffer):
        '''
            Reads log data when data descriptors are at end of buffer
            Returns a list of items read
        '''
        data = []
        descriptors = []
        if buf_size == 0:
            return data
        
        total_items = struct.unpack('<B', buffer[-1])[0]
        pos = buf_size - 1
        if buf_size == 1:
            if total_items != 0:
                log.error('Unknown data found in log data buffer')
            return data
        
        items_read = 0
        pos -= total_items
        while items_read < total_items:
            if pos <= 0:
                break
                log.error('Error, no place for data!')
            item_size = struct.unpack('<B', buffer[pos : pos + 1])[0]
            descriptors.append(item_size)
            items_read += 1
            pos += 1
        items_read = 0
        pos = 0
        while items_read < total_items:
            size = descriptors[items_read]
            item_data = buffer[pos : pos + size]
            data.append( [0, size, item_data] )
            pos += size
            items_read += 1
        
        return data

    def ReadLogDataBuffer(self, buffer, buf_size, strings_buffer):
        '''Returns a list of items read as [ type, size, raw_value_binary_string ]'''
        global debug_log_count

        data = []
        data_descriptors=[] # [ (data_index, offset, size, data_type), .. ]
        
        unknown, total_items = struct.unpack('<BB', buffer[0:2])
        pos = 2
        pos_debug = 0
        items_read = 0
        while items_read < total_items:
            if pos >= buf_size:
                log.error('Trying to read past buffer size!')
                break
            item_type, item_size = struct.unpack('<BB', buffer[pos:pos+2])
            pos += 2
            # item_type & 1 == 1, then 'private' flag is ON ?
            # item_type & 2 == 1, then '{public}' is in fmt_string
            if item_type in (0, 1): # number
                data.append([item_type, item_size, buffer[pos:pos+item_size]])
            elif item_type == 2: # %p (printed as hex with 0x prefix)
                data.append([item_type, item_size, buffer[pos:pos+item_size]])
            elif item_type in (0x20, 0x21, 0x22, 0x40, 0x41, 0x42, 0x31, 0x32): # string descriptor 0x22={public}%s 0x4x shows as %@ (if size=0, then '(null)') 
                # byte 0xAB A=type(0=num,1=len??,2=string in stringsbuf,4=object)  B=style (0=normal,1=private,2={public})
                # 0x3- is for %.*P object types
                offset, size = struct.unpack('<HH', buffer[pos:pos+4])
                data_descriptors.append( (len(data), offset, size, item_type) )
                data.append('')
            elif item_type & 0xF0 == 0x10: #0x10, 0x12 seen # Item length only, this is usually followed by 0x31 or 0x32 item_type. If length is 0, then only 0x31 is seen.
                # Seen in strings where predicate specifies string length Eg: %.4s
                if item_size != 4:
                    log.warning('Log data Item Length was 0x{:X} instead of 0x4. item_type=0x{:X}'.format(item_size, item_type))
                size = struct.unpack('<I', buffer[pos:pos+4])
                # Not using this information anywhere as it seems redundant!
            else:
                log.warning('item_type unknown (0x{:X})'.format(item_type))
                data.append([item_type, item_size, buffer[pos:pos+item_size]])
            if item_size == 0:
                log.warning('item_size was zero!')
                break
            pos += item_size
            items_read += 1
        pos_debug = pos
        if data_descriptors:
            for desc in data_descriptors:
                data_index, offset, size, data_type = desc
                if data_type == 0x21:
                    data[data_index] = [data_type, size, strings_buffer[offset : offset + size] if size else '<private>' ]
                elif data_type == 0x40:
                    data[data_index] = [data_type, size, buffer[pos + offset : pos + offset + size] if size else '(null)' ]
                    pos_debug += size
                elif data_type == 0x41: #Is this also a ref to something else at times??
                    data[data_index] = [data_type, size, strings_buffer[offset : offset + size] if size else '<private>' ]
                    pos_debug += size
                else:
                    data[data_index] = [data_type, size, buffer[pos + offset : pos + offset + size] ]
                    pos_debug += size
        #if (total_items > 0) or (buf_size > 2):
        #    pass #log.debug(hex(unknown) + " ** " + str(data))
        #unused buffer
        #if pos_debug < buf_size:
        #    pass #log.debug("Extra Data bytes ({}) @ {} ".format(buf_size-pos_debug, pos_debug) + " ## " + binascii.hexlify(buffer[pos_debug:]))
        return data

    def RecreateMsgFromFmtStringAndData(self, format_str, data, log_file_pos):
        msg = ''
        format_str_for_regex = format_str.replace('%%', '~') # %% is to be considered literal % but will interfere with our regex, so replace it
        format_str = format_str.replace('%%', '%')           # %% replaced with % in original. Since we aren't tokenizing, we use this hack
        len_format_str = len(format_str)
        data_count = len(data)
        format_str_consumed = 0 # No. of bytes read
        last_hit_end = 0
        for index, hit in enumerate(self.regex.finditer(format_str_for_regex)):
            #log.debug('{} {} all={}  {}  {} {} {}'.format(hit.start(), hit.end(), hit.group(0), hit.group(1), hit.group(2), hit.group(3), hit.group(4)))
            hit_len = hit.end() - hit.start()
            last_hit_end = hit.end()
            msg += format_str[format_str_consumed : hit.start()] # slice from end of last hit to begin of new hit
            format_str_consumed = last_hit_end
            # Now add data from this hit
            if index >= len(data):
                msg += '<decode: missing data>' # Message provided by 'log' program for missing data
                log.error('missing data for log @ 0x{:X}'.format(log_file_pos))
                continue
            data_item = data[index]
            # msg += data from this hit
            # data_item = [type, size, raw_data]
            try:
                custom_specifier = hit.group(1)
                flags_width_precision = hit.group(2).replace('\'', '')
                length_modifier = hit.group(3)
                specifier = hit.group(4)
                data_type = data_item[0]
                data_size = data_item[1]
                raw_data  = data_item[2]
                ## In below code , length_modifier has been removed from format string, let python string formatter handle rest
                ## It has the same format, except for flags, where single-qoute is not supported in python.
                if specifier in ('d', 'D', 'i', 'u', 'U', 'x', 'X', 'o', 'O'): # uint32 according to spec! but can be 4 or 8 bytes
                    number = 0
                    if data_size == 0: # size
                        if data_type & 0x1:
                            msg += '<private>'
                        else:
                            log.error('unknown err, size=0, data_type=0x{:X}'.format(data_type))
                    else: # size should be 4 or 8
                        if specifier in ('d', 'D'): # signed int32 or int64
                            specifier = 'd'  # Python does not support 'D'
                            if   data_size == 4: number = struct.unpack("<i", raw_data)[0] 
                            elif data_size == 8: number = struct.unpack("<q", raw_data)[0] 
                            else: log.error('Unknown length ({}) for number '.format(data_size))
                        else:
                            if   data_size == 4: number = struct.unpack("<I", raw_data)[0] 
                            elif data_size == 8: number = struct.unpack("<Q", raw_data)[0] 
                            else: log.error('Unknown length ({}) for number '.format(data_size))
                            if   specifier == 'U': specifier = 'u'  # Python does not support 'U'
                            elif specifier == 'O': specifier = 'o'  # Python does not support 'O'
                        msg += ('%'+ flags_width_precision + specifier) % number
                elif specifier in ('f', 'e', 'E', 'g', 'G', 'a', 'A', 'F'): # double 64 bit (or 32 bit float if 'lf')
                    number = 0
                    if data_size == 0: # size
                        if data_type & 0x1:
                            msg += '<private>'
                        else:
                            log.error('unknown err, size=0, data_type=0x{:X}'.format(data_type))
                    else:
                        if   data_size == 8: number = struct.unpack("<d", raw_data)[0]
                        elif data_size == 4: number = struct.unpack("<f", raw_data)[0]
                        else: log.error('Unknown length ({}) for float/double '.format(data_size))
                        msg += ('%'+ flags_width_precision + specifier) % number
                elif specifier in ('c', 'C', 's', 'S', '@'):  # c is Single char but stored as 4 bytes
                    # %C & %S are unicode char, but everything in log file would be encoded as utf8, so should be the same
                    # %@ is a utf8 representation of object
                    chars = ''
                    if data_size == 0:
                        if data_type == 0x40:
                            chars = '(null)'
                        elif data_type & 0x1:
                            chars = '<private>'
                    else:
                        try:
                            chars = raw_data.decode('utf8').rstrip('\x00')
                        except Exception as ex:
                            log.error('Error decoding utf8 in log @ 0x{:X}, data was "{}", error was {}'.format(log_file_pos, binascii.hexlify(raw_data), str(ex)))
                            chars = ''
                        chars = ('%'+ (flags_width_precision if flags_width_precision.find('*')==-1 else '')  + "s") % chars # Python does not like '%.*s'
                    msg += chars
                elif specifier == 'P':  # Pointer to data of different types!
                    if not custom_specifier:
                        msg += hit.group(0)
                        log.info("Unknown data object with no custom specifier in log @ 0x{:X}".format(log_file_pos))
                        continue
                    if data_size == 0:
                        if data_type & 0x1:
                            msg += '<private>'
                        continue

                    if custom_specifier.find('uuid_t') > 0:
                        if data_size == 0: # size
                            if data_type & 0x1:
                                msg += '<private>'
                            else: log.error('unknown err, size=0, data_type=0x{:X} in log @ 0x{:X}'.format(data_type, log_file_pos))
                        else:
                            uuid = UUID(bytes=raw_data)
                            msg += str(uuid).upper()
                    elif custom_specifier.find('odtypes:mbr_details') > 0:
                        unk = raw_data[0]
                        if unk == 'D': # 0x44
                            group, pos = ReadCStringAndEndPos(raw_data[1:], len(raw_data))
                            pos += 2
                            domain = ReadCString(raw_data[pos:], len(raw_data) - pos)
                            msg += 'group: {}@{}'.format(group, domain)
                        elif unk == '#': #0x23
                            uid = struct.unpack("<I", raw_data[1:5])[0]
                            domain = ReadCString(raw_data[5:], len(raw_data) - 5)
                            msg += 'user: {}@{}'.format(uid, domain)
                        else:
                            log.error("Unknown value for mbr_details found 0x{} in log @ 0x{:X}".format(unk.encode('hex'), log_file_pos))
                    elif custom_specifier.find('odtypes:nt_sid_t') > 0: 
                        msg += ReadNtSid(raw_data)
                    elif custom_specifier.find('location:SqliteResult') > 0:
                        number = struct.unpack("<I", raw_data)[0]
                        if number >= 0 and number <=28:
                            error_codes = [ 'SQLITE_OK','SQLITE_ERROR','SQLITE_INTERNAL','SQLITE_PERM','SQLITE_ABORT','SQLITE_BUSY',
                                            'SQLITE_LOCKED','SQLITE_NOMEM','SQLITE_READONLY','SQLITE_INTERRUPT','SQLITE_IOERR',
                                            'SQLITE_CORRUPT','SQLITE_NOTFOUND','SQLITE_FULL','SQLITE_CANTOPEN','SQLITE_PROTOCOL',
                                            'SQLITE_EMPTY','SQLITE_SCHEMA','SQLITE_TOOBIG','SQLITE_CONSTRAINT','SQLITE_MISMATCH',
                                            'SQLITE_MISUSE','SQLITE_NOLFS','SQLITE_AUTH','SQLITE_FORMAT','SQLITE_RANGE',
                                            'SQLITE_NOTADB','SQLITE_NOTICE','SQLITE_WARNING']
                            msg += error_codes[number]
                        elif number == 100: msg += 'SQLITE_ROW'
                        elif number == 101: msg += 'SQLITE_DONE'
                        else:
                            msg += str(number) + " - unknown sqlite result code"
                            #https://www.sqlite.org/c3ref/c_abort.html sqlite result codes
                    elif custom_specifier.find('network:sockaddr') > 0:
                        size, family = struct.unpack("<BB", raw_data[0:2])
                        if family == 0x1E: # AF_INET6 ipv6
                            port, flowinfo = struct.unpack("<HI", raw_data[2:8])
                            ipv6 = struct.unpack(">8H", raw_data[8:24])
                            ipv6_str = u'{:X}:{:X}:{:X}:{:X}:{:X}:{:X}:{:X}:{:X}'.format(ipv6[0],ipv6[1],ipv6[2],ipv6[3],ipv6[4],ipv6[5],ipv6[6],ipv6[7])#must be unicode
                            msg += ipaddress.ip_address(ipv6_str).compressed
                        elif family == 0x02: # AF_INET ipv4
                            port = struct.unpack("<H", raw_data[2:4])
                            ipv4 = struct.unpack("<BBBB", raw_data[4:8])
                            ipv4_str = '{}.{}.{}.{}'.format(ipv4[0],ipv4[1],ipv4[2],ipv4[3])
                            msg += ipv4_str # TODO- test this, not seen yet!
                        else:
                            log.error("Unknown sock family value 0x{:X} in log @ 0x{:X}".format(family, log_file_pos))
                    # elif custom_specifier.find('_CLDaemonStatusStateTrackerState') > 0:
                    #     msg += Read_CLDaemonStatusStateTrackerState(raw_data)
                    elif custom_specifier.find('_CLClientManagerStateTrackerState') > 0:
                        msg += Read_CLClientManagerStateTrackerState(raw_data)
                    else:
                        msg += hit.group(0)
                        log.info("Unknown custom data object type '{}' data size=0x{:X} in log @ 0x{:X}".format(custom_specifier, len(raw_data), log_file_pos))
                        pass #TODO
                elif specifier == 'p':  # Should be 8bytes to be displayed as uint 32/64 in hex lowercase no leading zeroes
                    number = ''
                    if data_size == 0: # size
                        if data_type & 0x1:
                            msg += '<private>'
                        else:
                            log.error('unknown err, size=0, data_type=0x{:X} in log @ 0x{:X}'.format(data_type, log_file_pos))
                    else: # size should be 8 or 4
                        if   data_size == 8: number = struct.unpack("<Q", raw_data)[0]
                        elif data_size == 4: number = struct.unpack("<I", raw_data)[0]
                        else: log.error('Unknown length ({}) for number in log @ 0x{:X}'.format(data_size, log_file_pos))
                        msg += ('%' + flags_width_precision + 'x') % number
            except:
                log.exception('exception for log @ 0x{:X}'.format(log_file_pos))
                msg += "E-R-R-O-R"

        if format_str_consumed < len_format_str:
            # copy remaining bytes from end of last hit to end of strings
            msg += format_str[last_hit_end:]
        elif format_str_consumed > len_format_str:
            log.error('format_str_consumed ({}) > len_format_str ({})'.format(format_str_consumed, len_format_str))

        return msg

    def DebugPrintLog(self, file_pos, cont_time, timestamp, thread, level_type, activity, pid, euid, ttl, p_name, lib, sub_sys, cat, msg, signpost):
        global debug_log_count
        log.debug('{} (0x{:X}) {} ({}) 0x{:X} {} 0x{:X} {} {} '.format(debug_log_count, file_pos, \
                    ReadAPFSTime(timestamp), cont_time, thread, level_type, activity, pid, euid, ttl, p_name) + \
                    ( '[{}] '.format(signpost) if signpost else '') + \
                      '{}: '.format(p_name) + \
                    ( '({}) '.format(lib) if lib else '') + \
                    ( '[{}:{}] '.format(sub_sys, cat) if sub_sys else '') + \
                    msg
                 )

    def DebugPrintTimestampFromContTime(self, ct, msg=''):
        '''Given a continuous time value, print its human readable form'''
        ts = FindClosestTimesyncItemInList(self.boot_uuid_ts_list, ct)
        time = ts.time_stamp + ct - ts.continuousTime
        log.debug("{} timestamp={}".format(msg, ReadAPFSTime(time)))

    def DebugCheckLogLengthRemaining(self, log_length, bytes_needed, log_abs_offset):
        '''Checks if we have enough space for extracting more elements'''
        if log_length < bytes_needed:
            log.error('Log data length (0x{:X}) < {} for log @ 0x{:X}!'.format(log_length, bytes_needed, log_abs_offset))
            raise ValueError('Not enough data in log data buffer!')

    def ProcessDataChunk(self, buffer, catalog, meta_chunk_index, debug_file_pos, logs):
        '''Read chunks with flag 0x600D'''
        global debug_log_count
        len_buffer = len(buffer)
        pos = 0
        chunk_meta = catalog.ChunkMetaInfo[meta_chunk_index]
        while (pos + 16) < len_buffer:
            tag, subtag, data_size = self.ParseChunkHeader(buffer[pos:pos+16], debug_file_pos + pos)
            pos += 16
            start_skew = pos % 8 # calculate deviation from 8-byte boundary for padding later
            proc_id1, proc_id2, ttl = struct.unpack('QII', buffer[pos:pos+16]) # ttl is not for type 6001, it means something else there!
            pos2 = 16
            proc_info = self.GetProcInfo(proc_id1, proc_id2, chunk_meta)
            log_file_pos = debug_file_pos + pos + pos2 - 32
            if not proc_info: # Error checking and skipping that chunk entry, so we can parse the rest
                log.error('Could not get proc_info, skipping log @ 0x{:X}'.format(log_file_pos))
                pos += data_size
                if ((pos - start_skew) % 8):
                    # sometimes no padding after privatedata. Try to detect null byte, if so pad it.
                    if (pos+1 < len_buffer) and (buffer[pos:pos+1] == b'\x00'): 
                        pad_len = 8 - ((pos - start_skew) % 8)
                        pos += pad_len
                    else:
                        log.warning('Avoided padding for log ending @ 0x{:X}'.format(debug_file_pos + pos))
            pid = proc_info.pid
            euid = proc_info.euid
            if tag == 0x6001: #Firehose
                offset_strings, strings_v_offset, unknown4, unknown5, continuousTime \
                  = struct.unpack('<HHHHQ', buffer[pos + pos2 : pos + pos2 + 16])
                pos2 = 32
                if strings_v_offset < 4096: #data_size - offset_strings > 0x10: # Has strings
                    size_priv_data = 4096 - strings_v_offset
                    private_strings = buffer[pos + data_size - size_priv_data : pos + data_size]
                else:
                    private_strings = ''

                num_logs_debug = 0

                ts = FindClosestTimesyncItemInList(self.boot_uuid_ts_list, continuousTime)
                self.DebugPrintTimestampFromContTime(continuousTime, "Type 6001")
                
                logs_end_offset = offset_strings + 16
                while pos2 < logs_end_offset:
                    # Log item 
                    log_start_pos = pos + pos2
                    start_skew = pos2 % 8
                    u1, u2, fmt_str_v_offset, thread, ct_rel, ct_rel_upper, log_data_len = struct.unpack('<HHIQIHH', buffer[pos + pos2 : pos + pos2 + 24])
                    pos2 += 24
                    
                    ct = continuousTime + (ct_rel | (ct_rel_upper << 32))
                    # processing
                    log_file_pos = debug_file_pos + pos + pos2 - 24 
                    #log.debug('log_file_pos=0x{:X}'.format(log_file_pos))

                    ts = FindClosestTimesyncItemInList(self.boot_uuid_ts_list, ct)
                    time = ts.time_stamp + ct - ts.continuousTime
                    #log.debug("Type 6001 LOG timestamp={}".format(ReadAPFSTime(time)))
                    try: # Big Exception block for any log uncaught exception
                        dsc_cache = catalog.FileObjects[proc_info.dsc_file_index] if (proc_info.dsc_file_index != -1) else None
                        ut_cache = catalog.FileObjects[proc_info.uuid_file_index]
                        p_name = ut_cache.library_name

                        senderImagePath = '' # Can be same as processImagePath
                        processImagePath = ut_cache.library_path
                        imageOffset = 0  # Same as senderProgramCounter
                        imageUUID = ''   # Same as senderImageUUID
                        processImageUUID = ut_cache.Uuid # Can be same as imageUUID
                        parentActivityIdentifier = 0

                        ut = None
                        format_str = ''
                        lib = '' # same as senderImage?
                        priv_str_len = 0      # when has_private_data
                        priv_str_v_offset = 0 # when has_private_data
                        sub_sys = ''
                        cat = ''
                        ttl = 0
                        act_id = [0]
                        has_msg_in_uuidtext = False # main_exe     [apple]
                        has_ttl = False             # has_rules    [apple]
                        has_act_id = False
                        has_subsys = False
                        has_alternate_uuid = False  # absolute     [apple]
                        has_msg_in_dsc = False      # shared_cache [apple]
                        has_other_act_id = False
                        has_unique_pid = False
                        has_private_data = False
                        has_sp_name = False
                        has_data_ref = False
                        has_activity_unk = False # unknown flag
                        is_activity = False
                        log_type = 'Default'
                        u1_upper_byte = (u1 >> 8)
                        is_signpost = False
                        signpost_string = 'spid 0x%x,'
                        signpost_name =''
                        if u1_upper_byte & 0x80: # signpost (Default)
                            is_signpost = True
                            if u1_upper_byte & 0xC0 == 0xC0: signpost_string += ' system,'  # signpostScope
                            else:                            signpost_string += ' process,' # signpostScope
                            if u1_upper_byte & 0x82 == 0x82: signpost_string += ' end'      # signpostType
                            elif u1_upper_byte & 0x81 == 0x81: signpost_string += ' begin'
                            else:                            signpost_string += ' event'
                        elif u1_upper_byte == 0x01: 
                            log_type = 'Info'
                            if (u1 & 0x0F) == 0x02:
                                log_type ='Activity'
                                is_activity = True
                        elif u1_upper_byte == 0x02: log_type = 'Debug'
                        elif u1_upper_byte == 0x10: log_type = 'Error'
                        elif u1_upper_byte == 0x11: log_type = 'Fault'

                        if u2 & 0x7000: 
                            log.info('Unknown flag for u2 encountered u2=0x{:4X} @ 0x{:X} ct={}'.format(u2, log_file_pos, ct))
                            #raise ValueError('Unk u2 flag')
                        if u2 & 0x8000: has_sp_name = True

                        if u2 & 0x0800: has_data_ref = True
                        if u2 & 0x0400: has_ttl = True
                        if u2 & 0x0200: has_subsys = True if (not is_activity) else False 
                        if u2 & 0x0200: has_other_act_id = True if is_activity else False
                        if u2 & 0x0100: has_private_data = True if (not is_activity) else False
                        if u2 & 0x0100: has_activity_unk = True if is_activity else False

                        if u2 & 0x00E0: # E=1110
                            log.info('Unknown flag for u2 encountered u2=0x{:4X} @ 0x{:X} ct={}'.format(u2, log_file_pos, ct))
                            #raise ValueError('Unk u2 flag')
                        if u2 & 0x0010: has_unique_pid = True

                        if u2 & 0x0008: has_alternate_uuid = True
                        if u2 & 0x0004: has_msg_in_dsc = True
                        if u2 & 0x0002: has_msg_in_uuidtext = True
                        if u2 & 0x0001: has_act_id = True

                        log_data_len2 = log_data_len
                        pos3 = pos2
                        if is_activity: # cur_aid [apple]
                            u5, u6 = struct.unpack('<II', buffer[pos + pos3 : pos + pos3 + 8]) # check for activity
                            if u6 == 0x80000000:
                                act_id.append(u5)
                                pos3 += 8
                                log_data_len2 -= 8
                            else:
                                log.error('Expected activityID, got something else!')
                            if has_unique_pid:
                                proc_id = struct.unpack('<Q', buffer[pos + pos3 : pos + pos3 + 8])[0]
                                pos3 += 8
                                log_data_len2 -= 8
                            if has_act_id: # another act_id # new_aid [apple]
                                u5, u6 = struct.unpack('<II', buffer[pos + pos3 : pos + pos3 + 8])
                                if u6 == 0x80000000:
                                    act_id.append(u5)
                                    pos3 += 8
                                    log_data_len2 -= 8
                                else:
                                    log.error('Expected activityID, got something else!')
                            if has_other_act_id: # yet another act_id # other_aid [apple]
                                u5, u6 = struct.unpack('<II', buffer[pos + pos3 : pos + pos3 + 8])
                                if u6 == 0x80000000:
                                    act_id.append(u5)
                                    pos3 += 8
                                    log_data_len2 -= 8
                                else:
                                    log.error('Expected activityID, got something else!')
                        else:
                            if has_act_id:
                                u5, u6 = struct.unpack('<II', buffer[pos + pos3 : pos + pos3 + 8])
                                if u6 == 0x80000000:
                                    act_id.append(u5)
                                    pos3 += 8
                                    log_data_len2 -= 8
                                else:
                                    log.error('Expected activityID, got something else!')

                        if has_private_data:
                            if private_strings:    
                                priv_str_v_offset, priv_str_len = struct.unpack('<HH', buffer[pos + pos3 : pos + pos3 + 4])
                                pos3 += 4
                                log_data_len2 -= 4
                            else:
                                log.error('Did not read priv_str_v_offset as no private_strings are present @ log 0x{:X}! is_activity={}'.format(log_file_pos, bool(is_activity)))

                        u5 = struct.unpack('<I', buffer[pos + pos3 : pos + pos3 + 4])[0]
                        pos3 += 4
                        log_data_len2 -= 4

                        if has_alternate_uuid:
                            if not has_msg_in_uuidtext: # Then 2 bytes (uuid_file_index) instead of UUID
                                uuid_file_id = struct.unpack('<h', buffer[pos + pos3 : pos + pos3 + 2])[0]
                                pos3 += 2
                                log_data_len2 -= 2
                                uuid_found = False
                                for extra_ref in proc_info.extra_file_refs:
                                    if (extra_ref.id == uuid_file_id) and \
                                    ( (u5 >= extra_ref.v_offset) and ( (u5-extra_ref.v_offset) < extra_ref.data_size) ):  # found it
                                        ut = catalog.FileObjects[extra_ref.uuid_file_index]
                                        format_str = ut.ReadFmtStringFromVirtualOffset(fmt_str_v_offset)
                                        imageUUID = ut.Uuid
                                        senderImagePath = ut.library_path
                                        imageOffset = u5 - extra_ref.v_offset
                                        uuid_found = True
                                        break
                                if not uuid_found:
                                    log.error('no uuid found for absolute pc - uuid_file_id was {} u5=0x{:X} fmt_str_v_offset=0x{:X} @ 0x{:X} ct={}'.format(uuid_file_id, u5, fmt_str_v_offset, log_file_pos, ct))
                                    format_str = '<compose failure [missing precomposed log]>' # error message from log utility
                            else:             # UUID
                                file_path = binascii.hexlify(buffer[pos + pos3 : pos + pos3 + 16]).upper()
                                pos3 += 16
                                log_data_len2 -= 16
                                ## try to get format_str and lib from uuidtext file
                                ut = None
                                # search in existing files, likely will not find it here!
                                for obj in catalog.FileObjects:
                                    if obj.file.filename == file_path:
                                        ut = obj
                                        break
                                if not ut: # search in other_uuidtext, as we may have seen this earlier
                                    ut = self.other_uuidtext.get(file_path, None)
                                if not ut: # Not found, so open and parse new file
                                    uuidtext_full_path = self.vfs.path_join(self.uuidtext_folder_path, file_path[0:2], file_path[2:])
                                    ut = Uuidtext(self.vfs.get_virtual_file(uuidtext_full_path, 'Uuidtext'), UUID(file_path))
                                    self.other_uuidtext[file_path] = ut # Add to other_uuidtext, so we don't have to parse it again
                                    if not ut.Parse():
                                        ut = None
                                        log.error('Error parsing uuidtext file {} @ 0x{:X} ct={}'.format(uuidtext_full_path, log_file_pos, ct))
                                if ut:
                                    format_str = ut.ReadFmtStringFromVirtualOffset(fmt_str_v_offset)
                                    p_name = ut_cache.library_name
                                    lib = ut.library_name
                                    imageUUID = ut.Uuid
                                    senderImagePath = ut.library_path
                                else:
                                    log.debug("Could not read from uuidtext {} @ 0x{:X} ct={}".format(file_path, log_file_pos, ct))
                        
                        if not is_activity:
                            if has_subsys:
                                item_id = struct.unpack('<H', buffer[pos + pos3 : pos + pos3 + 2])[0]
                                pos3 += 2
                                log_data_len2 -= 2
                                sub_sys, cat = proc_info.GetSubSystemAndCategory(item_id)
                            
                            if has_ttl:
                                ttl = struct.unpack('<B', buffer[pos + pos3 : pos + pos3 + 1])[0]
                                pos3 += 1
                                log_data_len2 -= 1

                            if has_data_ref: #This is a ref to an object stored as type 0x0602 blob
                                data_ref_id = struct.unpack('<H', buffer[pos + pos3 : pos + pos3 + 2])[0]
                                pos3 += 2
                                log_data_len2 -= 2
                                log.debug('Data reference ID = {:4X}'.format(data_ref_id))
                                
                            if is_signpost:
                                spid_val = struct.unpack('<Q', buffer[pos + pos3 : pos + pos3 + 8])[0]
                                pos3 += 8
                                log_data_len2 -= 8
                                signpost_string = signpost_string % (spid_val)

                            if has_sp_name:
                                sp_name_ref = struct.unpack('<I', buffer[pos + pos3 : pos + pos3 + 4])[0]
                                pos3 += 4
                                log_data_len2 -= 4

                        # Get format_str and lib now
                        if has_msg_in_uuidtext: # u2 & 0x0002: # msg string in uuidtext file
                            imageOffset = u5
                            if has_alternate_uuid: # another uuidtext file was specified, already read that above
                                if has_sp_name:
                                    signpost_name = ut.ReadFmtStringFromVirtualOffset(sp_name_ref)
                            else:
                                imageUUID = ut_cache.Uuid
                                senderImagePath = ut_cache.library_path
                                format_str = ut_cache.ReadFmtStringFromVirtualOffset(fmt_str_v_offset)
                                if has_sp_name:
                                    signpost_name = ut_cache.ReadFmtStringFromVirtualOffset(sp_name_ref)
                        elif has_msg_in_dsc: # u2 & 0x0004: # msg string in dsc file
                            if has_sp_name:
                                try:
                                    signpost_name, c_a, c_b = dsc_cache.ReadFmtStringAndEntriesFromVirtualOffset(sp_name_ref)
                                except:
                                    log.error("Could not get signpost name! @ 0x{:X} ct={}".format(log_file_pos, ct))
                            cache_b1 = dsc_cache.GetUuidEntryFromVirtualOffset(u5)
                            if cache_b1:
                                lib = cache_b1[4] # senderimage_name
                                imageUUID = cache_b1[2]
                                senderImagePath = cache_b1[3]
                                imageOffset = u5 - cache_b1[0]

                            try:
                                if fmt_str_v_offset & 0x80000000: # check for highest bit
                                    format_str = "%s"
                                    log.debug("fmt_str_v_offset highest bit set @ 0x{:X} ct={}".format(log_file_pos, ct))
                                else:
                                    format_str, cache_a, cache_b = dsc_cache.ReadFmtStringAndEntriesFromVirtualOffset(fmt_str_v_offset)
                            except:
                                log.error('Failed to get DSC msg string @ 0x{:X} ct={}'.format(log_file_pos, ct))
                        elif has_alternate_uuid: pass #u2 & 0x0008: # Parsed above
                        else:
                            log.warning("No message string flags! @ 0x{:X} ct={}".format(log_file_pos, ct))

                        if log_data_len2:
                            strings_slice = ''
                            if has_private_data:
                                if private_strings:
                                    strings_start_offset = 0
                                    strings_len = len(private_strings)
                                    strings_start_offset = priv_str_v_offset - strings_v_offset
                                    if (strings_start_offset > len(private_strings)) or (strings_start_offset < 0):
                                        log.error('Error calculating strings virtual offset @ 0x{:X} ct={}'.format(log_file_pos, ct))
                                    strings_slice = private_strings[strings_start_offset : strings_start_offset + priv_str_len]
                                else:
                                    log.error('Flag has_private_data but no strings present! @ 0x{:X} ct={}'.format(log_file_pos, ct))
                            else:
                                strings_slice = ''
                            if u1 & 0x3 == 0x3: # data_descriptor_at_buffer_end
                                log_data = self.ReadLogDataBuffer2(buffer[pos + pos3 : pos + pos3 + log_data_len2], log_data_len2, strings_slice)
                            else:
                                log_data = self.ReadLogDataBuffer(buffer[pos + pos3 : pos + pos3 + log_data_len2], log_data_len2, strings_slice)
                        else:
                            log_data = None
                        if has_data_ref:
                            unique_ref = data_ref_id << 64 | ct
                            log_data = self.large_data.get(unique_ref, None)
                            if log_data:
                                log_data = log_data = self.ReadLogDataBuffer(log_data, len(log_data), '')
                            else:
                                log.error('Data Reference not found for unique_ref=0x{:X} ct={}!'.format(unique_ref, ct))
                                format_str = "<decode: missing data>"
                                # TODO - Sometimes this data is in another file, create a mechanism to deal with that
                                # Eg: Logdata.Livedata.tracev3 will reference entries from Persist\*.tracev3 
                                #  There are very few of these in practice.

                        log_msg = self.RecreateMsgFromFmtStringAndData(format_str, log_data, log_file_pos) if log_data else format_str
                        if len(act_id) > 2: parentActivityIdentifier = act_id[-2]
                        logs.append([self.file.filename, log_file_pos, ct, time, thread, log_type, act_id[-1], parentActivityIdentifier, \
                                        pid, euid, ttl, p_name, lib, sub_sys, cat,\
                                        signpost_name, signpost_string if is_signpost else '', 
                                        imageOffset, imageUUID, processImageUUID, senderImagePath, processImagePath,
                                        log_msg                            
                                    ])
                    except Exception as ex:
                        log.exception("Exception while processing log @ 0x{:X} ct={}, skipping that log entry!".format(log_file_pos, ct))
                    ##
                    debug_log_count += 1
                    
                    pos2 += log_data_len
                    #padding
                    if ((pos2 - start_skew) % 8) != 0: 
                        pos2 += 8 - ((pos2 - start_skew) % 8)
                    num_logs_debug += 1

                log.debug("Parsed {} type 6001 logs".format(num_logs_debug))
               
                pos += data_size
                if ((pos - start_skew) % 8):
                    # sometimes no padding after privatedata. Try to detect null byte, if so pad it.
                    if (pos+1 < len_buffer) and (buffer[pos:pos+1] == b'\x00'): 
                        pad_len = 8 - ((pos - start_skew) % 8)
                        pos += pad_len
                    else:
                        log.warning('Avoided padding for firehose chunk ending @ 0x{:X}'.format(debug_file_pos + pos))
            elif tag == 0x6002: # Oversize
                ct, data_ref_id, data_len = struct.unpack('<QII', buffer[pos + pos2 : pos + pos2 + 16])
                pos2 += 16
                data = buffer[pos + pos2 : pos + pos2 + data_len]
                self.large_data[data_ref_id << 64 | ct] = data
                
                pos2 += data_len
                ## Debug print
                ts = FindClosestTimesyncItemInList(self.boot_uuid_ts_list, ct)
                time = ts.time_stamp + ct - ts.continuousTime
                log.debug("Type 6002 timestamp={} ({}), data_ref_id=0x{:X} @ 0x{:X}".format(ReadAPFSTime(time), ct, data_ref_id, log_file_pos))
                pos += data_size
                if (pos - start_skew) % 8:
                    pad_len = 8 - ((pos - start_skew) % 8)
                    pos += pad_len
            elif tag == 0x6003: # State
                log_type = 'State'
                ct, activity_id, un7 = struct.unpack("<QII", buffer[pos + pos2 : pos + pos2 + 16])
                pos2 += 16
                uuid = UUID(bytes = buffer[pos + pos2 : pos + pos2 + 16])
                pos2 += 16
                data_type, data_len = struct.unpack('<II', buffer[pos + pos2 : pos + pos2 + 8])
                pos2 += 8
                if data_type == 1:
                    pos2 += 128  # type 1 does not have any strings, it is blank or random bytes
                else:
                    obj_type_str_1 = ReadCString(buffer[pos + pos2 : pos + pos2 + 64])
                    pos2 += 64
                    obj_type_str_2 = ReadCString(buffer[pos + pos2 : pos + pos2 + 64]) 
                    pos2 += 64

                name = ReadCString(buffer[pos + pos2 : pos + pos2 + 64], 64)
                pos2 += 64
                # datatype  1=plist, 2=custom object, 3=unknown data object
                log_msg = ''
                if data_len:
                    data = buffer[pos + pos2 : pos + pos2 + data_len]
                    if data_type == 1: # plist  # serialized NS/CF object [Apple]
                        try:
                            plist = biplist.readPlistFromString(data)
                            log_msg = unicode(plist)
                        except:
                            log.exception('Problem reading plist from log @ 0x{:X} ct={}'.format(log_file_pos, ct))
                    elif data_type == 2:  #custom object, not being read by log utility in many cases!
                        log.error('Did not read data of type {}, t1={}, t2={}, length=0x{:X} from log @ 0x{:X} ct={}'.format(data_type, obj_type_str_1, obj_type_str_2, data_len, log_file_pos, ct))
                    elif data_type == 3:  # custom [Apple] #TODO - read non-plist data
                        if obj_type_str_1 == 'location' and obj_type_str_2 == '_CLClientManagerStateTrackerState':
                            log_msg = Read_CLClientManagerStateTrackerState(data)
                        else:
                            log.error('Did not read data of type {}, t1={}, t2={}, length=0x{:X} from log @ 0x{:X} ct={}'.format(data_type, obj_type_str_1, obj_type_str_2, data_len, log_file_pos, ct))
                    else:
                        log.error('Unknown data of type {}, t1={}, t2={}, length=0x{:X} from log @ 0x{:X} ct={}'.format(data_type, obj_type_str_1, obj_type_str_2, data_len, log_file_pos, ct))           
                    pos2 += data_len

                try: # for any uncaught exception
                    ut_cache = catalog.FileObjects[proc_info.uuid_file_index]
                    p_name = ut_cache.library_name

                    senderImagePath = '' # Can be same as processImagePath
                    processImagePath = ut_cache.library_path
                    imageOffset = 0  # Same as senderProgramCounter
                    imageUUID = uuid
                    processImageUUID = ut_cache.Uuid

                    ts = FindClosestTimesyncItemInList(self.boot_uuid_ts_list, ct)
                    time = ts.time_stamp + ct - ts.continuousTime
                    #log.debug("Type 6003 timestamp={}".format(ReadAPFSTime(time)))

                    logs.append([self.file.filename, log_file_pos, ct, time, 0, log_type, 0, 0, \
                                pid, euid, ttl, p_name, str(uuid).upper(), '', '',\
                                '', '', 
                                imageOffset, imageUUID, processImageUUID, senderImagePath, processImagePath, 
                                name + "\n" + log_msg                        
                                ])
                except:
                    log.exception("Exception while processing logtype 'State' @ 0x{:X} ct={}, skipping that log entry!".format(log_file_pos, ct))
                debug_log_count += 1

                pos += data_size
                if (pos - start_skew) % 8:
                    pad_len = 8 - ((pos - start_skew) % 8)
                    pos += pad_len
            else:
                log.info("Unexpected tag value 0x{:X} @ 0x{:X} (Expected 0x6001, 0x6002 or 0x6003)".format(tag, log_file_pos))
                pos += data_size
                pad_len = (pos - start_skew) % 8
                if pad_len:
                    pos += pad_len
            #padding,moved to individual sections due to anomaly with few files, where privatedata in 0x6001 has no padding after!

    
    def GetProcInfo(self, proc_id1, proc_id2, chunk_meta):
        proc_info = chunk_meta.ProcInfos.get( proc_id2 | (proc_id1 << 32) , None)
        if proc_info == None:
            log.error("Could not find proc_info with proc_id1={} proc_id2={}".format(proc_id1, proc_id2))
        return proc_info

    def Parse(self, log_list_process_func=None):
        '''Parse the traceV3 file, returns True/False.
           'log_list_process_func' is a function the caller provides to 
           process a list of logs. It gets called periodically as logs are extracted.
           Its syntax is log_list_process_func(logs_list, tracev3_object)
           Here log_list = [ log_1, log_2, .. ], where each log_x item is a tuple
           log_x = ( log_file_pos, continuous_time, time, thread, log_type, 
                    activity_id, parent_activity_id, 
                    pid, euid, ttl, p_name, lib, sub_system, category,
                    signpost_name, signpost_string, 
                    image_offset, image_UUID, process_image_UUID, 
                    sender_image_path, process_image_path,
                    log_msg
                   ) 
        '''
        log.debug("-"*100 + "\r\nParsing traceV3 file {}".format(self.file.filename))
        f = self.file.open()
        if not f:
            return False
        try:
            file_size = self.file.get_file_size()
            chunk_header = f.read(16)
            tag, subtag, data_length = self.ParseChunkHeader(chunk_header, 0)
            if tag != 0x1000:
                log.info('Wrong signature in traceV3 file, got 0x{:X} instead of 0x1000'.format(tag))
                return False
            if subtag != 0x11:
                log.error('Cannot process this version of unified logging, version=0x{:X}'.format(subtag))
                return False
            
            buffer = f.read(data_length) # fileheader_data + items
            self.ParseFileHeader(buffer, data_length)
            
            pos = 16 + data_length
            catalog = None
            meta_chunk_index = 0
            global debug_log_count
            debug_log_count = 0
            uncompressed_file_pos = pos
            logs = []
            while pos < file_size:
                f.seek(pos)
                chunk_header = f.read(16)
                tag, subtag, data_length = self.ParseChunkHeader(chunk_header, uncompressed_file_pos)
                buffer = f.read(data_length)
                # Process buffer here
                if tag == 0x600B:
                    meta_chunk_index = 0
                    catalog = self.ProcessMetaChunk(buffer, uncompressed_file_pos + 16) # debug_file_pos will be for uncompressed tracev3 only!
                    uncompressed_file_pos += 16 + data_length
                elif tag == 0x600D:
                    uncompressed_buffer = DecompressChunkData(buffer, len(buffer))
                    self.ProcessDataChunk(uncompressed_buffer, catalog, meta_chunk_index, uncompressed_file_pos + 16, logs)
                    meta_chunk_index += 1
                    uncompressed_file_pos += 16 + len(uncompressed_buffer)
                else:
                    log.info("Unknown header for chunk - 0x{:X} , skipping chunk @ 0x{:X}!".format(tag, pos))
                    uncompressed_file_pos += 16 + data_length
                if data_length % 8: # Go to QWORD boundary
                    data_length += 8 - (data_length % 8)
                if uncompressed_file_pos % 8: # just for the uncompressed file pos
                    uncompressed_file_pos += 8 - (data_length % 8)
                pos = pos + 16 + data_length
                if log_list_process_func and (len(logs) > 100000):
                    log_list_process_func(logs, self)
                    logs = []
            # outside loop, end of file reached, write remaining logs
            if log_list_process_func and (len(logs) > 0):
                log_list_process_func(logs, self)
        except:
            log.exception('traceV3 Parser error')
        return True
        
class CachedFiles():
    ''' 
        Optimization measure to parse and hold open file pointers for uuidtext/dsc files,
        so they are not parsed again and again
    '''
    def __init__(self, v_fs):
        self.vfs = v_fs
        self.cached_dsc = {}      # Key = UUID string uppercase (no seperators), Val = Dsc object
        self.cached_uuidtext = {} # Key = UUID string uppercase (no seperators), Val = Uuidtext object

    def ParseFolder(self, uuidtext_folder_path):
        '''Parse the uuidtext folder specified and parse all uuidtext/dsc files, adding them to the cache'''
        try:
            # dsc
            dsc_path = self.vfs.path_join(uuidtext_folder_path, 'dsc')
            entries = self.vfs.listdir(dsc_path)
            for dsc_name in entries:
                if len(dsc_name) == 32:                    
                    dsc = Dsc(self.vfs.get_virtual_file(self.vfs.path_join(dsc_path, dsc_name), 'Dsc'))
                    dsc.Parse()
                    self.cached_dsc[dsc_name] = dsc

            # uuidtext - can't have this or python will complain of too many open files!
            # entries = self.vfs.listdir(uuidtext_folder_path)
            # index = 0
            # for index in range(0x100):
            #     folder_name = '{:02X}'.format(index)
            #     #if vfs.path_exists(folder_path):
            #     if folder_name in entries:
            #         folder_path = self.vfs.path_join(uuidtext_folder_path, folder_name)
            #         uuid_names = self.vfs.listdir(folder_path)
            #         for uuid_name in uuid_names:
            #             if len(uuid_name) == 30: # filtering out possibly other files there!
            #                 uuidtext_path = self.vfs.path_join(folder_path, uuid_name)
            #                 ut = Uuidtext(self.vfs.get_virtual_file(uuidtext_path, 'Uuidtext'), UUID(folder_name + uuid_name))
            #                 ut.Parse()
            #                 self.cached_uuidtext[folder_name + uuid_name] = ut
            #     else:
            #         log.debug(folder_name + ' does not exist')
        except Exception:
            log.exception('')


class Uuidtext():
    def __init__(self, v_file, uuid):
        self.file = v_file
        self.flag1 = 0
        self.flag2 = 0
        self.num_entries = 0
        self.entries = []   # [ [range_start_offset, data_offset, data_len], [..] , ..]
        self.library_path = ''
        self.library_name = ''
        self.Uuid = uuid

    def ReadFmtStringFromVirtualOffset(self, v_offset):
        if not self.file.is_valid: return '<compose failure [UUID]>' # value returned by 'log' program if uuidtext is not found
        if v_offset & 0x80000000: return '%s' # if highest bit is set
        for entry in self.entries:
            if (entry[0] <= v_offset) and ((entry[0] + entry[2]) > v_offset):
                rel_offset = v_offset - entry[0]
                f = self.file.file_pointer
                f.seek(entry[1] + rel_offset)
                buffer = f.read(entry[2] - rel_offset)
                return ReadCString(buffer)
        #Not found
        log.error('Invalid bounds 0x{:X} for {}'.format(v_offset, str(self.Uuid))) # This is error msg from 'log'
        return '<compose failure [UUID]>'

    def Parse(self):
        '''Parse the uuidtext file, returns True/False'''
        f = self.file.open()
        if not f:
            return False
        try:
            buffer = f.read(16) # header
            if buffer[0:4] != b'\x99\x88\x77\x66':
                log.info('Wrong signature in uuidtext file, got 0x{} instead of 0x99887766'.format(binascii.hexlify(buffer[0:4])))
                return False
            self.flag1, self.flag2, self.num_entries = struct.unpack("<III", buffer[4:16])
            # Read entry structures
            buffer = f.read(8 * self.num_entries)
            pos = 0
            data_offset = 16 + (8 * self.num_entries)
            for i in range(self.num_entries):
                range_start_offset, data_len = struct.unpack("<II", buffer[pos:pos+8])
                self.entries.append([range_start_offset, data_offset, data_len])
                pos += 8
                data_offset += data_len
            # Read library path
            f.seek(data_offset)
            path_buffer = f.read(1024)
            self.library_path = ReadCString(path_buffer)
            self.library_name = os.path.basename(self.library_path)

        except:
            log.exception('Uuidtext Parser error')
            self.file.is_valid = False
        return True

class Dsc():
    def __init__(self, v_file):
        self.file = v_file
        self.version = 0
        self.num_range_entries = 0
        self.num_uuid_entries = 0
        self.range_entries = []  # [ [uuid_index, v_off, data_offset, data_len], [..], ..] # data_offset is absolute in file
        self.uuid_entries  = []  # [ [v_off,  size,  uuid,  lib_path, lib_name], [..], ..] # v_off is virt offset

    def FindVirtualOffsetEntries(self, v_offset):
        '''Return tuple (range_entry, uuid_entry) where range_entry[xx].size <= v_offset'''
        ret_range_entry = None
        ret_uuid_entry = None
        for a in self.range_entries:
            if (a[1] <= v_offset) and ((a[1] + a[3]) > v_offset):
                ret_range_entry = a
                ret_uuid_entry = self.uuid_entries[a[0]]
                return (ret_range_entry, ret_uuid_entry)
        #Not found
        log.error('Failed to find v_offset in Dsc!')
        return (None, None)

    def ReadFmtStringAndEntriesFromVirtualOffset(self, v_offset):
        range_entry, uuid_entry = self.FindVirtualOffsetEntries(v_offset)
        if range_entry:
            rel_offset = v_offset - range_entry[1]
            f = self.file.file_pointer
            f.seek(range_entry[2] + rel_offset)
            buffer = f.read(range_entry[3] - rel_offset)
            return (ReadCString(buffer), range_entry, uuid_entry)
        return '<compose failure [UUID]>'

    def GetUuidEntryFromUuid(self, uuid):
        '''Find a uuid_entry from its UUID value'''
        for b in self.uuid_entries:
            if b[2] == uuid:
                return b
        #Not found
        log.error('Failed to find uuid {} in Dsc!'.format(str(uuid)))
        return b

    def GetUuidEntryFromVirtualOffset(self, v_offset):
        '''Returns uuid_entry where uuid_entry[xx].v_off <= v_offset and falls within allowed size'''
        for b in self.uuid_entries:
            if (b[0] <= v_offset) and ((b[0] + b[1]) > v_offset):
                rel_offset = v_offset - b[0]
                return b
        #Not found
        log.error('Failed to find uuid_entry for v_offset 0x{:X} in Dsc!'.format(v_offset))
        return None

    def DebugPrintDsc(self):
        log.debug("DSC version={} file={}".format(self.version, self.file.filename))
        log.debug("Range entry values")
        for a in self.range_entries:
            log.debug("{} {} {} {}".format(a[0], a[1], a[2], a[3]))
        log.debug("Uuid entry values")
        for b in self.uuid_entries:
            log.debug("{} {} {} {} {}".format(b[0], b[1], b[2], b[3], b[4]))

    def Parse(self):
        '''Parse the dsc file, returns True/False'''
        f = self.file.open()
        if not f:
            return False
        try:
            buffer = f.read(16) # header
            if buffer[0:4] != b'hcsd':
                log.info('Wrong signature in DSC file, got 0x{} instead of 0x68637364 (hcsd)'.format(binascii.hexlify(buffer[0:4])))
                return False
            self.version, self.num_range_entries, self.num_uuid_entries = struct.unpack("<III", buffer[4:16])
            # Read range structures
            buffer = f.read(16 * self.num_range_entries)
            pos = 0
            for i in range(self.num_range_entries):
                uuid_index, v_off, data_offset, data_len = struct.unpack("<IIII", buffer[pos:pos+16])
                self.range_entries.append([uuid_index, v_off, data_offset, data_len])
                pos += 16
            # Read uuid_entry structures
            buffer = f.read(28 * self.num_uuid_entries)
            pos = 0
            for i in range(self.num_uuid_entries):
                v_off, size = struct.unpack("<II", buffer[pos:pos+8])
                uuid = UUID(bytes=buffer[pos+8:pos+24])
                data_offset = struct.unpack("<I", buffer[pos+24:pos+28])[0]
                f.seek(data_offset)
                path_buffer = f.read(1024) # File path should not be >1024
                lib_path = ReadCString(path_buffer)
                lib_name = os.path.basename(lib_path)
                self.uuid_entries.append([v_off, size, uuid, lib_path, lib_name])
                pos += 28
        except:
            log.exception('DSC Parser error')
            self.file.is_valid = False
        return True

def GetBootUuidTimeSyncList(ts_list, uuid):
    '''
        Searches ts_list for the boot uuid provided and returns the 
        timesync items list for that uuid
    '''
    for ts in ts_list:
        if ts.header.boot_uuid == uuid:
            return ts.items
    log.error("Could not find boot uuid {} in Timesync!".format(uuid))
    return None

def FindClosestTimesyncItem(ts_list, uuid, continuousTime):
    '''Searches ts_list for the boot_id specified by uuid and time'''
    found_boot_id = False
    for ts in ts_list:
        if ts.header.boot_uuid == uuid:
            found_boot_id = True
            return FindClosestTimesyncItemInList(ts.items, continuousTime)

    if not found_boot_id:
        log.error("Could not find boot uuid {} in Timesync!".format(uuid))
    return None

def FindClosestTimesyncItemInList(ts_items, continuousTime):
    '''Returns the closest timesync item from the provided ts_items list'''
    closest_tsi = ts_items[0]
    for item in ts_items:
        if item.continuousTime > continuousTime:
            break
        else: # must be <
            closest_tsi = item
    return closest_tsi

class Timesync:
    def __init__(self, header):
        self.header = header
        self.items = []
        #self.items_dict = {} # unused , use later for optimization

class TimesyncHeader:

    def __init__(self, sig, unk1, boot_uuid, ts_numer, ts_denom, ts, bias, is_dst):
        self.signature = sig
        self.unknown1  = unk1
        self.boot_uuid = boot_uuid
        self.ts_numerator   = ts_numer
        self.ts_denominator = ts_denom
        self.time_stamp = ts
        self.bias_minutes   = bias
        self.is_dst = (is_dst == 1) # 1 = DST

class TimesyncItem:
    '''Timesync item object'''
    def __init__(self, ts_unknown, cont_time, ts, bias, is_dst):
        #self.signature = sig # "Ts  " = sig?
        self.ts_unknown = ts_unknown
        self.continuousTime = cont_time
        self.time_stamp = ts
        self.bias_minutes = bias
        self.is_dst = (is_dst == 1) # 1 = DST

def ReadTimesyncFile(buffer, ts_list):
    try:
        pos = 0
        size = len(buffer)
        while pos < size:
            sig, header_size, unk1  = struct.unpack("<HHI", buffer[pos:pos+8])
            if sig != 0xBBB0:
                log.error("not the right signature for Timesync header, got 0x{:04X} instead of 0x{:04X}, pos was 0x{:08X}".format(sig, 0x0030BBB0, pos))
                break
            uuid = UUID(bytes=buffer[pos+8:pos+24])
            ts_numer, ts_denom, t_stamp, tz, is_dst = struct.unpack("<IIqiI", buffer[pos+24:pos+48])
            ts_header = TimesyncHeader(sig, unk1, uuid, ts_numer, ts_denom, t_stamp, tz, is_dst)
            pos += header_size # 0x30 (48) by default
            if header_size != 0x30:
                log.info("Timesync header was 0x{:X} bytes instead of 0x30(48) bytes!".format(size))
            log.debug("TIMEHEAD {}  0x{:016X}  {} {}".format(uuid, t_stamp, ReadAPFSTime(t_stamp), 'boot'))
            #TODO - TEST search ts_list for existing, not seen so far
            existing_ts = None
            for ts in ts_list:
                if ts.header.boot_uuid == uuid:
                    existing_ts = ts
                    break
            if existing_ts:
                ts_obj = existing_ts
            else:
                ts_obj = Timesync(ts_header)
                ts_list.append(ts_obj)
                # Adding header timestamp as Ts type too with cont_time = 0
                ts_obj.items.append(TimesyncItem(0, 0, t_stamp, tz, is_dst))
            while pos < size:
                if buffer[pos:pos+4] == b'Ts \x00':
                    ts_unknown, cont_time, t_stamp, bias, is_dst = struct.unpack("<IqqiI", buffer[pos+4:pos+32])
                    ts_obj.items.append(TimesyncItem(ts_unknown, cont_time, t_stamp, bias, is_dst))
                    log.debug("TIMESYNC {}  0x{:016X}  {} {}".format(uuid, t_stamp, ReadAPFSTime(t_stamp), ts_unknown))
                else:
                    break # break this loop, parse as header
                pos += 32
    except Exception as ex:
        log.exception("Exception reading TimesyncFile")
    
def ReadTimesyncFolder(path, ts_list, vfs):
    '''Reads files in the timesync folder specified by 'path' and populates ts_list 
       with timesync entries.
       vfs = VirtualFileSystem object
    '''
    try:
        entries = vfs.listdir(path)
        for entry in sorted(entries): # sort the files by name, so continuous time will be sequential automatically
            if entry.endswith(".timesync"):
                file_path = vfs.path_join(path, entry)
                log.debug('Trying to read timesync file {}'.format(file_path))
                f = vfs.get_virtual_file(file_path, 'TimeSync').open()
                if f:
                    buffer = f.read() # should be a fairly small file!
                    ReadTimesyncFile(buffer, ts_list)
                    f.close()
            else:
                log.error("In Timesync folder, found non-ts file {}".format(entry))
    except Exception:
        log.exception('')

def DebugPrintTSRead(ts_list):
    for ts in ts_list:
        h = ts.header
        log.debug("HEADER = {} {} {} {} {} {}".format(h.uuid, h.flags1, h.flags2, ReadAPFSTime(h.time_stamp), -h.bias/60.0, h.is_dst))
        for item in ts.items:
            log.debug('ITEM={} {} {} {} {}'.format(item.ts_unknown, item.continuousTime, ReadAPFSTime(item.time_stamp), -item.bias/60., item.is_dst))
