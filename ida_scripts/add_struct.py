import os
import idaapi
from idc import *

sid = AddStrucEx(-1, "PARTITION_TABLE_ENTRY", 0)
AddStrucMember(sid, "status", 0, FF_BYTE, -1 ,1)
AddStrucMember(sid, "chsFirst", 1, FF_BYTE, -1 ,3)
AddStrucMember(sid, "type", 4, FF_BYTE, -1 ,1)
AddStrucMember(sid, "chsLast", 5, FF_BYTE, -1 ,3)
AddStrucMember(sid, "lbaStart", 8, FF_DWRD, -1 ,4)
AddStrucMember(sid, "size", 12, FF_DWRD, -1 ,4)

sid_table = AddStrucEx(-1, "PARTITION_TABLE", 0)
AddStrucMember(sid_table, "partitions", 0, FF_STRU, sid ,64)