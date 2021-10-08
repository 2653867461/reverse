#pragma once


#define COMMON_ENCRYPT_XOR(buffer,size,xorValue)		\
{														\
for (int i = 0; i < (size); ++i)						\
	(buffer)[i] ^= (xorValue);							\
}