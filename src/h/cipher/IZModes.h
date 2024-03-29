#ifndef IZECB_H
#define IZECB_H

#include "../../../include/IZCrypt.h"
#include "../Source.h"

izStatus IZEncryptECB(void (*EncFunc) (uint8_t*, const uint8_t*, uint8_t*), 
	const uint8_t* vKey, 
	const uint8_t* vIn, 
	size_t sInSize, 
	uint8_t* vOut, 
	size_t* psOutSize, 
	size_t sBlockSize);

izStatus IZDecryptECB(
	void (*DecFunc) (uint8_t*, const uint8_t*, uint8_t*), 
	const uint8_t* vKey, 
	const uint8_t* vIn, 
	size_t sInSize, 
	uint8_t* vOut, 
	size_t* psOutSize, 
	size_t sBlockSize);

izStatus IZEncryptDecryptCTR(
	void (*EncFunc) (uint8_t*, const uint8_t*, uint8_t*), 
	const uint8_t* vKey, 
	const uint8_t* vIn, 
	size_t sInSize, 
	uint8_t* vOut, 
	size_t* psOutSize, 
	size_t sBlockSize, 
	const uint8_t* vIv, 
	size_t sIvSize,
	uint16_t FirstParam);

izStatus IZEncryptDecryptOFB(
	void (*EncFunc) (uint8_t*, const uint8_t*, uint8_t*), 
	const uint8_t* vKey, 
	const uint8_t* vIn, 
	size_t sInSize, 
	uint8_t* vOut, 
	size_t* psOutSize, 
	size_t sBlockSize, 
	const uint8_t* vIv, 
	size_t sIvSize,
	uint16_t uS,
	uint16_t uM);

static void izAddCTR8(uint8_t* uCTR, size_t sIvSize);

static void IZPaddingX80(
	const uint8_t* vIn, 
	uint8_t* vOut, 
	size_t sBlockSize, 
	int r_bytes);

#endif