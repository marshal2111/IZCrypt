#include "../h/cipher/IZECB.h"

izStatus IZEncryptECB(void (*enc_func) (uint8_t*, uint8_t*, uint8_t*), const uint8_t* key, const uint8_t* in, 
	size_t in_size_bytes, uint8_t* out, size_t* psOutSize, size_t block_size)
{
	izStatus status = IZStatusSuccess;

	size_t sOutSize = 0; 
	uint8_t blockSize_bytes = block_size / 8;
	uint8_t buff [blockSize_bytes];
	uint8_t enc_buff [blockSize_bytes];
	uint8_t num_blocks = in_size_bytes / blockSize_bytes;

	for (int i = 0; i < num_blocks; i++) {
		memcpy(buff, in + i * blockSize_bytes, blockSize_bytes);
		enc_func(key, buff, enc_buff);
		memcpy(out + i * blockSize_bytes, enc_buff, blockSize_bytes);
	}

	sOutSize = in_size_bytes;

	uint8_t r_bytes = in_size_bytes % blockSize_bytes;
	if (r_bytes != 0) {
		memcpy(buff, in + blockSize_bytes * num_blocks, r_bytes);
		buff[r_bytes] = 0x80; // дополняем байтом 10000000
		for (int i = r_bytes + 1; i < blockSize_bytes; ++i)
		{
			buff[i] = 0x00; // дополняем байтами 00000000
		}
		enc_func(key, buff, enc_buff);
		memcpy(out + blockSize_bytes * num_blocks, enc_buff, blockSize_bytes);

		sOutSize += blockSize_bytes;
	 }

	 *psOutSize = sOutSize;

	return status;
}

izStatus IZDecryptECB(void (*dec_func) (uint8_t*, uint8_t*, uint8_t*), const uint8_t* key, const uint8_t* in, 
	size_t in_size_bytes, uint8_t* out, size_t block_size)
{
	uint8_t blockSize_bytes = block_size / 8;
	uint8_t buff [blockSize_bytes];
	uint8_t dec_buff [blockSize_bytes];
	uint8_t num_blocks = in_size_bytes / blockSize_bytes;

	for (int i = 0; i < num_blocks; i++) {
		memcpy(buff, in + i * blockSize_bytes, blockSize_bytes);
		dec_func(key, buff, dec_buff);
		memcpy(out + i * blockSize_bytes, dec_buff, blockSize_bytes);
	}

}