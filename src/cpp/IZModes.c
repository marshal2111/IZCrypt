#include "../h/cipher/IZModes.h"

izStatus IZEncryptECB(void (*EncFunc) (uint8_t*, uint8_t*, uint8_t*), const uint8_t* vKey, const uint8_t* vIn, 
	size_t sInSize, uint8_t* vOut, size_t* psOutSize, size_t sBlockSize)
{
	izStatus status = IZStatusSuccess;

	size_t sOutSize = 0; 
	uint8_t numBlocks = sInSize / sBlockSize;

	for (int i = 0; i < numBlocks; i++) {
		EncFunc(vKey, vIn + i * sBlockSize, vOut + i * sBlockSize);
	}

	sOutSize = numBlocks * sBlockSize;

	//Padding 
	uint8_t r_bytes = sInSize % sBlockSize;

	if (r_bytes != 0) {
		uint8_t buff[sBlockSize];
		IZPaddingX80(vIn, sInSize, buff, sBlockSize, numBlocks, r_bytes);
		EncFunc(vKey, buff, vOut + sBlockSize * numBlocks);
		sOutSize += sBlockSize;
	 }

	 *psOutSize = sOutSize;

	return status;
}

izStatus IZDecryptECB(void (*DecFunc) (uint8_t*, uint8_t*, uint8_t*), const uint8_t* vKey, const uint8_t* vIn, 
	size_t sInSize, uint8_t* vOut, size_t sBlockSize)
{
	uint8_t numBlocks = sInSize / sBlockSize;

	for (int i = 0; i < numBlocks; i++) {
		DecFunc(vKey, vIn + i * sBlockSize, vOut + i * sBlockSize);
	}

}

void IZPaddingX80(const uint8_t* vIn, size_t sInSize, uint8_t* vOut, size_t sBlockSize, int numBlocks,
	int r_bytes) 
{
	memcpy(vOut, vIn + sBlockSize * numBlocks, r_bytes);
	vOut[r_bytes] = 0x80; // дополняем байтом 10000000
	for (int i = r_bytes + 1; i < sBlockSize; ++i)
	{
		vOut[i] = 0x00; // дополняем байтами 00000000
	}
}