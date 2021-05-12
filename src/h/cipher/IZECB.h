#ifndef IZECB_H
#define IZECB_H


void IZEncryptECB(void (*enc_func) (uint8_t*, uint8_t*, uint8_t*), uint8_t* key, uint8_t* in, 
	uint8_t* out, uint8_t block_size, uint8_t size);


void IZDecryptECB(void (*enc_func) (uint8_t*, uint8_t*, uint8_t*), uint8_t* key, uint8_t* in, 
	uint8_t* out, uint8_t block_size, uint8_t size);
