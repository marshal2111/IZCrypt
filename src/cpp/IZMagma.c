#include "../h/cipher/IZMagma.h"
#include "../h/cipher/IZSwap.h"

const uint8_t izMagmaSbox [8][16] = {
			{12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1} ,
			{6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15} , 
			{11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0} ,
			{12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11} ,
			{7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12} ,
			{5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0} ,
			{8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7} ,
			{1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2}
		};


static uint32_t izT32(uint32_t a)
{
	uint32_t res = 0;
	
	for (uint32_t i = 0; i < 8; ++i) {
		res = (res << 4) | izMagmaSbox[7 - i][(a >> (28 - i * 4)) & 0xF];
	} 
	
	return res;
}	

static uint32_t izCycleShift(uint32_t a, uint8_t offset)
{
	return (a << offset) | (a >> (32 - offset));
}

static uint32_t izG32(uint32_t k, uint32_t a)
{
	return izCycleShift(izT32(a + k), 11);
}

static void izG32_(uint32_t* a1, uint32_t* a0, uint32_t k)
{
	uint32_t a = *a1;
	*a1 = *a0;
	*a0 = izG32(k, *a0) ^ a;
}

static int64_t izG64_(uint32_t a1, uint32_t a0, uint32_t k)
{
	uint64_t res = ((uint64_t)(izG32(k, a0) ^ a1)) << 32;
	return res | a0;
}

static void izGenerateKeys(uint8_t* key, uint32_t* keys)
{
	for (int i = 0; i < 8; ++i) {
		for (int j = 0; j < 4; ++j) {
			keys[i] = (keys[i] << 8) | key[j + 4 * i];
		}
	}

	for (int i = 8; i < 16; ++i)
		keys[i] = keys[i - 8];

	for (int i = 16; i < 24; ++i)
		keys[i] = keys[i - 16];

	for (int i = 24; i < 32; ++i)
		keys[i] = keys[47 - i];
}

void izMagmaEncrypt(uint8_t* key, uint8_t* in, uint8_t* out)
{
	uint32_t a1, a0;

	memcpy(&a0, in + 4, 4);
	memcpy(&a1, in, 4);

	a1 = izSwap32(a1);
	a0 = izSwap32(a0);

	uint32_t keys[32];
	izGenerateKeys(key, keys);

	for (int i = 0; i < 31; ++i) {
		izG32_(&a1, &a0, keys[i]);
	}

	uint64_t g64 = izG64_(a1, a0, keys[31]);
	g64 = izSwap64(g64);

	memcpy(out, &g64, 8); 
}

void izMagmaDecrypt(uint8_t* key, uint8_t* in, uint8_t* out)
{
	uint32_t a1, a0;

	memcpy(&a0, in + 4, 4);
	memcpy(&a1, in, 4);

	a1 = izSwap32(a1);
	a0 = izSwap32(a0);

	uint32_t keys[32];
	izGenerateKeys(key, keys);

	for (int i = 31; i > 0; --i) {
		izG32_(&a1, &a0, keys[i]);
	}


	uint64_t g64 = izG64_(a1, a0, keys[0]);
	g64 = izSwap64(g64);
	memcpy(out, &g64, 8);
}

