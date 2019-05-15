import os
import idaapi
from idc import *

def add_struct_def():
    sid_partition_entry = AddStrucEx(-1, "PARTITION_TABLE_ENTRY", 0)

    AddStrucMember(sid_partition_entry, "status", 0, FF_BYTE, -1 ,1)
    AddStrucMember(sid_partition_entry, "chsFirst", 1, FF_BYTE, -1 ,3)
    AddStrucMember(sid_partition_entry, "type", 4, FF_BYTE, -1 ,1)
    AddStrucMember(sid_partition_entry, "chsLast", 5, FF_BYTE, -1 ,3)
    AddStrucMember(sid_partition_entry, "lbaStart", 8, FF_DWRD, -1 ,4)
    AddStrucMember(sid_partition_entry, "size", 12, FF_DWRD, -1 ,4)

    sid_table = AddStrucEx(-1, "PARTITION_TABLE", 0)
    AddStrucMember(sid_table, "partitions", 0, FF_STRU, sid , 64)

    return sid_table

# -----------------------------------------------------------------------
def accept_file(li, n):
    """
    Check if the file is of supported format

    @param li: a file-like object which can be used to access the input data
    @param n : format number. The function will be called with incrementing 
               number until it returns zero
    @return: 0 - no more supported formats
             string "name" - format name to display in the chooser dialog
             dictionary { 'format': "name", 'options': integer }
               options: should be 1, possibly ORed with ACCEPT_FIRST (0x8000)
               to indicate preferred format
    """

    # we support only one format per file
    if n > 0:
        return 0

    # check size of the file
    file_size = li.size()
    if file_size < 512:
        return 0

    # check MBR signature
    li.seek(510, os.SEEK_SET)
    mbr_sign = li.read(2)
    if mbr_sign[0] != '\x55' or mbr_sign[1] != '\xAA':
        return 0

    # all the checks are passed
    return 'MBR'

# -----------------------------------------------------------------------
def load_file(li, neflags, format):
    
    """
    Load the file into database

    @param li: a file-like object which can be used to access the input data
    @param neflags: options selected by the user, see loader.hpp
    @return: 0-failure, 1-ok
    """

    # Select the PC processor module
    idaapi.set_processor_type("metapc", SETPROC_ALL|SETPROC_FATAL)

    # read MBR into buffer
    li.seek(0, os.SEEK_SET); buf = li.read(li.size())
    
    seg = idaapi.segment_t()
    start = 0x7C00

    size = len(buf)
    end  = start + size
        
    # Create the segment
    seg.startEA = start
    seg.endEA   = end
    seg.bitness = 0 # 16-bit
    idaapi.add_segm_ex(seg, "seg0", "CODE", 0)

    # Copy the bytes
    idaapi.mem2base(buf, start, end)

    # add entry point
    idaapi.add_entry(start, start, "start", 1)

    strid = add_struct_def()    
    idaapi.set_name(start + 0x1BE, "MBR_PARTITION_TABLE", idaapi.SN_CHECK)
    str_size = idaapi.get_struc_size(strid)
    idaapi.doStruct(start + 0x1BE, str_size, strid)

    idaapi.set_name(510, "MBR_SIGN", idaapi.SN_CHECK)

    # Mark for analysis
    AutoMark(start, AU_CODE)


    return 1