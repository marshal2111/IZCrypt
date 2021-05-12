#include "../h/cipher/IZMagma.h"

static uint32_t t32(uint32_t a)
{
	uint32_t res = 0;
	
	for (uint32_t i = 0; i < 8; ++i) {
		res = (res << 4) | p64[7 - i][(a >> (28 - i * 4)) & 0xF];
		//printf("%u\n", res);
	} 
	
	return res;
}	

static uint32_t cycle_shift(uint32_t a, uint8_t offset)
{
	return (a << offset) | (a >> (32 - offset));
}

static uint32_t g32(uint32_t k, uint32_t a)
{
	return cycle_shift(t32(a + k), 11);
}

static void G32(uint32_t* a1, uint32_t* a0, uint32_t k)
{
	uint32_t a = *a1;
	*a1 = *a0;
	*a0 = g32(k, *a0) ^ a;
}

static int64_t G64_(uint32_t a1, uint32_t a0, uint32_t k)
{
	uint64_t res = ((uint64_t)(g32(k, a0) ^ a1)) << 32;
	return res | a0;
}

void izMagmaEncrypt(uint8_t* key, uint8_t* in, uint8_t* out)
{
	uint32_t a1 = 0;
	uint32_t a0 = 0;

	for (int i = 0; i < 4; ++i) {
		a1 = (a1 << 4) | in[i];
	}

	for (int i = 4; i < 8; ++i) {
		a0 = (a0 << 4) | in[i];
	}

	uint32_t* keys[32];
	generate_keys(key, keys);

	for (int i = 0; i < 31; ++i) {
		G32(&a1, &a0, keys[i]);
		//printf("%X %X\n", a1, a0);
	}

	out = (uint8_t*) &G64_(a1, a0, keys[31]); 
}

void izMagmaDecrypt(uint8_t* key, uint8_t* in, uint8_t* out)
{
	uint32_t a1 = 0;
	uint32_t a0 = 0;

	for (int i = 0; i < 4; ++i) {
		a1 = (a1 << 4) | in[i];
	}

	for (int i = 4; i < 8; ++i) {
		a0 = (a0 << 4) | in[i];
	}

	uint32_t* keys[32];
	generate_keys(key, keys);

	for (int i = 31; i > 0; --i) {
		G32(&a1, &a0, keys[i]);
		//printf("%X %X\n", a1, a0);
	}

	out = (uint8_t*) &G64_(a1, a0, keys[0]);
}

static generate_keys(uint8_t* key, uint32_t* keys)
{
	for (int i = 0; i < 8; ++i) {
		for (int j = 0; j < 4; ++j) {
			keys[i] = (keys[i] << 8) | key[j + 4 * i];
		}
		// printf("%X\n", keys[i]);
	}

	for (int i = 8; i < 16; ++i)
		keys[i] = keys[i - 8];

	for (int i = 16; i < 24; ++i)
		keys[i] = keys[i - 16];

	for (int i = 24; i < 32; ++i)
		keys[i] = keys[47 - i];
	// for (int i = 0; i < 32; ++i) 
	// 	printf("%i, %X\n", i + 1, keys[i]);
}