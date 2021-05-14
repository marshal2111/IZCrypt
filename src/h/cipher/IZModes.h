#ifndef IZECB_H
#define IZECB_H

#include "../../../include/IZCrypt.h"
#include "../Source.h"

izStatus IZEncryptECB(void (*EncFunc) (uint8_t*, uint8_t*, uint8_t*), const uint8_t* vKey, const uint8_t* vIn, 
	size_t sInSize, uint8_t* vOut, size_t* psOutSize, size_t sBlockSize);


izStatus IZDecryptECB(void (*DecFunc) (uint8_t*, uint8_t*, uint8_t*), const uint8_t* vKey, const uint8_t* vIn, 
	size_t sInSize, uint8_t* vOut, size_t sBlockSize);

void IZPaddingX80(const uint8_t* vIn, size_t sInSize, uint8_t* vOut, size_t sBlockSize, int numBlocks,
	int r_bytes);


#endif