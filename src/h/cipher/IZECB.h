#ifndef IZECB_H
#define IZECB_H

#include "../../../include/IZCrypt.h"
#include "../Source.h"

izStatus IZEncryptECB(void (*enc_func) (uint8_t*, uint8_t*, uint8_t*), const uint8_t* key, const uint8_t* in, 
	size_t in_size_bytes, uint8_t* out, size_t* psOutSize, size_t block_size);


izStatus IZDecryptECB(void (*dec_func) (uint8_t*, uint8_t*, uint8_t*), const uint8_t* key, const uint8_t* in, 
	size_t in_size_bytes, uint8_t* out, size_t block_size);

#endif