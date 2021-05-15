#include "../h/cipher/IZModes.h"
#include "../h/cipher/IZSwap.h"
#include "../h/cipher/IZMagma.h"

izStatus IZEncryptECB(
	void (*EncFunc) (uint8_t*, uint8_t*, uint8_t*), 
	const uint8_t* vKey, 
	const uint8_t* vIn, 
	size_t sInSize, 
	uint8_t* vOut, 
	size_t* psOutSize, 
	size_t sBlockSize)
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

izStatus IZDecryptECB(
	void (*DecFunc) (uint8_t*, uint8_t*, uint8_t*), 
	const uint8_t* vKey, 
	const uint8_t* vIn, 
	size_t sInSize, 
	uint8_t* vOut, 
	size_t sBlockSize)
{
	uint8_t numBlocks = sInSize / sBlockSize;

	for (int i = 0; i < numBlocks; i++) {
		DecFunc(vKey, vIn + i * sBlockSize, vOut + i * sBlockSize);
	}

}

izStatus IZEncryptDecryptCTR(
	void (*EncFunc) (uint8_t*, uint8_t*, uint8_t*), 
	const uint8_t* vKey, 
	const uint8_t* vIn, 
	size_t sInSize, 
	uint8_t* vOut, 
	size_t* psOutSize, 
	size_t sBlockSize, 
	const uint8_t* vIv, 
	size_t sIvSize,
	uint16_t uS)
{
	izStatus sStatus = IZStatusSuccess;

	if ((sIvSize != 4) && (EncFunc == &izMagmaEncrypt)) {
		return IZStatusError;
	}
	if ((vIv == NULL) || (sIvSize == 0) || (uS == 0)) {
		return IZStatusInvalidParameter;;
	}

	/*---Инициализация счетчика CTR---*/
	uint8_t uCTR[sIvSize];
	memcpy(uCTR, vIv, sIvSize);
	for (int i = sIvSize; i < sIvSize * 2; ++i) {
		uCTR[i] = 0x00;
	}
	/*---Конец инициализации---*/

	uint8_t r_bytes = sInSize % uS;
	uint8_t numBlocks = sInSize / uS;
	uint8_t uEncryptedCTR[sIvSize * 2];

	for (int i = 0; i < numBlocks; ++i) {
		EncFunc(vKey, uCTR, uEncryptedCTR);
		for (int j = 0; j < uS; ++j) {
			vOut[j + i * uS] = uEncryptedCTR[sIvSize * 2 - uS + j] ^ vIn[i * uS + j];
		}
		izAddCTR8(uCTR, sIvSize); 
	}
	EncFunc(vKey, uCTR, uEncryptedCTR);	
	for (int j = 0; j < r_bytes; ++j) {
			vOut[j + numBlocks * uS] = uEncryptedCTR[sIvSize * 2 - r_bytes + j] ^ vIn[numBlocks * uS + j];
	}

	*psOutSize = sInSize;

	return sStatus;
}	


void izAddCTR8(uint8_t* uCTR, size_t sIvSize)
{
	uint64_t uBuffer = 0;

	memcpy(&uBuffer, uCTR, sIvSize * 2);
	uBuffer = izSwap64(uBuffer);
	uBuffer += 1;
	uBuffer = izSwap64(uBuffer);
	memcpy(uCTR, &uBuffer, sIvSize * 2);
}


void IZPaddingX80(
	const uint8_t* vIn, 
	size_t sInSize,
	uint8_t* vOut, 
	size_t sBlockSize, 
	int numBlocks,
	int r_bytes) 
{
	memcpy(vOut, vIn + sBlockSize * numBlocks, r_bytes);
	vOut[r_bytes] = 0x80; // дополняем байтом 10000000
	for (int i = r_bytes + 1; i < sBlockSize; ++i) {
		vOut[i] = 0x00; // дополняем байтами 00000000
	}
}