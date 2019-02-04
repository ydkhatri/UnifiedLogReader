#!/usr/bin/env python
# 
# This script will produce a decompressed .tracev3 file for analysis.
# Provide either a file or a folder as argument, it will decompress all .tracev3 
# files found recursively (if folder is provided). Output will be in same folder
# as original tracev3 file and will have .dec appended to name.
# 
# (c) Yogesh Khatri 2018
#
# Tested on Sierra, High Sierra and Mojave

import binascii
import os
import struct
import sys

import lz4.block


def DecompressFile(input_path, output_path):
    try:
        with open(input_path, 'rb') as trace_file:
            with open(output_path, 'wb') as out_file:
                index = 0
                header = trace_file.read(4)
                while header:
                    begin_pos = trace_file.tell() - 4
                    trace_file.seek(begin_pos + 8)
                    struct_len = struct.unpack('<Q', trace_file.read(8))[0]
                    #print "index={} pos=0x{:X}".format(index, begin_pos), binascii.hexlify(header)

                    trace_file.seek(begin_pos)
                    block_data = trace_file.read(16 + struct_len)
                    if header == b'\x00\x10\x00\x00': # header
                        out_file.write(block_data) # boot_uuid header, write to output directly
                    elif header[0] == b'\x0B':
                        out_file.write(block_data) # uncompressed, write to output directly
                    elif header[0] == b'\x0D': 
                        if block_data[16:20] in [b'bv41', b'bv4-']:
                            uncompressed = b''
                            last_uncompressed = b''
                            chunk_start = 16 # bv** offset
                            chunk_header = block_data[chunk_start:chunk_start + 4]
                            while (struct_len > chunk_start) and (chunk_header != b'bv4$'):
                                if chunk_header == b'bv41':
                                    uncompressed_size, compressed_size = struct.unpack('<II', block_data[chunk_start + 4:chunk_start + 12])
                                    last_uncompressed = lz4.block.decompress(block_data[chunk_start + 12: chunk_start + 12 + compressed_size], uncompressed_size, dict=last_uncompressed)
                                    chunk_start += 12 + compressed_size
                                    uncompressed += last_uncompressed
                                elif chunk_header == b'bv4-':
                                    uncompressed_size = struct.unpack('<I', block_data[chunk_start + 4:chunk_start + 8])[0]
                                    uncompressed += block_data[chunk_start + 8:chunk_start + 8 + uncompressed_size]
                                    chunk_start += 8 + uncompressed_size
                                else:
                                    print 'Unknown compression value {} @ 0x{:X} - {}'.format(binascii.hexlify(chunk_header), begin_pos + chunk_start, chunk_header)
                                    break
                                chunk_header = block_data[chunk_start:chunk_start + 4]
                            ###
                            out_file.write(block_data[0:8]) # Same Header !
                            out_file.write(struct.pack('<Q', len(uncompressed))) # New size
                            out_file.write(uncompressed)
                        else:
                            print 'Unknown compression type', binascii.hexlify(block_data[16:20])
                    else:
                        print 'Unknown header value encountered : {}, struct_len=0x{:X}'.format(binascii.hexlify(header), struct_len)
                        out_file.write(block_data[0:8]) # Same Header !
                        out_file.write(block_data) # Same data!
                    if struct_len % 8: # Go to QWORD boundary on input
                        struct_len += 8 - (struct_len % 8)
                    if out_file.tell() % 8: # Go to QWORD boundary on output
                        out_file.write(b'\x00\x00\x00\x00\x00\x00\x00'[0:(8-out_file.tell() % 8)])
                    trace_file.seek(begin_pos + 16 + struct_len)
                    header = trace_file.read(4)
                    index += 1
    except Exception as ex:
        print 'Exception', str(ex)
        return False
    return True

def RecurseDecompressFiles(input_path):
    files = os.listdir(input_path)
    for file_name in files:
        input_file_path = os.path.join(input_path, file_name)
        if file_name.lower().endswith('.tracev3'):
            print "Processing file - ", input_file_path
            DecompressFile(input_file_path, input_file_path + ".dec")
        elif os.path.isdir(input_file_path):
            RecurseDecompressFiles(input_file_path)
if len(sys.argv) == 1:
    print "Not enough arguments, provide the traceV3 file's path or a folder path to recurse extract tracev3 files"
else:
    input_path = sys.argv[1]

    if os.path.isdir(input_path):
        RecurseDecompressFiles(input_path)
    else:
        print "Processing file - ", input_path
        DecompressFile(input_path, input_path + ".dec")
