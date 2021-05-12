#include "../h/cipher/IZECB.h"

izStatus IZEncryptECB(void (*enc_func) (uint8_t*, uint8_t*, uint8_t*), const uint8_t* key, const uint8_t* in, 
	size_t in_size_bytes, uint8_t* out, size_t block_size)
{
	izStatus status = IZStatusSuccess;

	uint8_t buff[8];
	uint8_t enc_buff[8];
	uint8_t num_blocks = (in_size_bytes * 8) / block_size;
	for (int i = 0; i < num_blocks; i++) {
		for (int j = 0; j < 8; ++j) {
			buff[j] = in[j + i * block_size];
		}
		enc_func(key, buff, enc_buff);
		for (int j = 0; j < 8; ++j) {
			out[j + i * block_size] = enc_buff[j];
		}
	}

	// uint8_t mod = (size * 8) % block_size;
	// if (mod != 0) {
	// 	for (int i = 0; i < mod / 8; ++i)
	// 	{
	// 		buff[i] = in[i + block_size * num_blocks]
	// 	}
	// 	for (int i = mod / 8; i < 8; ++i)
	// 	{
	// 		buff[i] = 0xF;
	// 	}
	// 	for (int i = 0; i < 8; ++i)
	// 	{
	// 		magma_encrypt(key, buff, enc_buff);
	// 		for (int j = 0; j < 8; ++j) {
	// 			out[j + i * block_size] = enc_buff[j];
	// 		}
	// 	}
	// }
	return status;
}

izStatus IZDecryptECB(void (*dec_func) (uint8_t*, uint8_t*, uint8_t*), const uint8_t* key, const uint8_t* in, 
	size_t in_size_bytes, uint8_t* out, size_t block_size)
{
	uint8_t buff[8];
	uint8_t dec_buff[8];
	uint8_t num_blocks = (in_size_bytes * 8) / block_size;
	for (int i = 0; i < num_blocks; i++) {
		for (int j = 0; j < 8; ++j) {
			buff[j] = in[j + i * block_size];
		}
		dec_func(key, buff, dec_buff);
		for (int j = 0; j < 8; ++j) {
			out[j + i * block_size] = dec_buff[j];
		}
	}
	// uint8_t mod = (size * 8) % block_size;
	// if (mod != 0) {
	// 	for (int i = 0; i < mod / 8; ++i)
	// 	{
	// 		buff[i] = in[i + block_size * num_blocks]
	// 	}
	// 	for (int i = mod / 8; i < 8; ++i)
	// 	{
	// 		buff[i] = 0xF;
	// 	}
	// 	for (int i = 0; i < 8; ++i)
	// 	{
	// 		magma_decrypt(key, buff, enc_buff);
	// 		for (int j = 0; j < 8; ++j) {
	// 			out[j + i * block_size] = enc_buff[j];
	// 		}
	// 	}
	// }
}