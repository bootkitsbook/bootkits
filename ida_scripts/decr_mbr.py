import idaapi
from idaapi import Choose2

start_ea = 0x7C19

for ix in xrange(0xCF):
	print ix
	byte_to_decr = idaapi.get_byte(start_ea + ix)
	to_rotate = (0xCF - ix) % 8
	byte_decr = (byte_to_decr >> to_rotate) | (byte_to_decr << (8 - to_rotate))

	idaapi.patch_byte(start_ea + ix, byte_decr)
