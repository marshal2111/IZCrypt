#include "../h/cipher/IZModes.h"
#include "../h/cipher/IZSwap.h"
#include "../h/cipher/IZMagma.h"

izStatus IZEncryptECB(
	void (*EncFunc) (uint8_t*, const uint8_t*, uint8_t*), 
	const uint8_t* vKey, 
	const uint8_t* vIn, 
	size_t sInSize, 
	uint8_t* vOut, 
	size_t* psOutSize, 
	size_t sBlockSize)
{
	izStatus sStatus = IZStatusSuccess;	

	size_t sOutSize = 0; 
	uint32_t numBlocks = sInSize / sBlockSize;

	for (uint32_t i = 0; i < numBlocks; i++) {
		EncFunc(vKey, vIn + i * sBlockSize, vOut + i * sBlockSize);
	}

	uint8_t r_Bytes = sInSize % sBlockSize;
	uint8_t vPaddingBuff[sBlockSize];

	IZPaddingX80(vIn + sBlockSize * numBlocks, vPaddingBuff, sBlockSize, r_Bytes);
	EncFunc(vKey, vPaddingBuff, vOut + sBlockSize * numBlocks);

	sOutSize = (numBlocks + 1) * sBlockSize;

	*psOutSize = sOutSize;

	return sStatus;
}

izStatus IZDecryptECB(
	void (*DecFunc) (uint8_t*, const uint8_t*, uint8_t*), 
	const uint8_t* vKey, 
	const uint8_t* vIn, 
	size_t sInSize, 
	uint8_t* vOut, 
	size_t* psOutSize, 
	size_t sBlockSize)
{
	izStatus sStatus = IZStatusSuccess;	

	uint32_t numBlocks = sInSize / sBlockSize;

	for (uint32_t i = 0; i < numBlocks; i++) {
		DecFunc(vKey, vIn + i * sBlockSize, vOut + i * sBlockSize);
	}

	uint8_t i = 0;
	while (vOut[numBlocks * sBlockSize - i] != 0x80) { i++; }

	*psOutSize = sInSize - i;

	return sStatus;

}

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
	uint32_t numBlocks = sInSize / uS;
	uint8_t uEncryptedCTR[sIvSize * 2];

	for (uint32_t i = 0; i < numBlocks; ++i) {
		EncFunc(vKey, uCTR, uEncryptedCTR);
		for (uint16_t j = 0; j < uS; ++j) {
			vOut[j + i * uS] = uEncryptedCTR[sIvSize * 2 - uS + j] ^ vIn[i * uS + j];
		}
		izAddCTR8(uCTR, sIvSize); 
	}	
	EncFunc(vKey, uCTR, uEncryptedCTR);	
	for (uint16_t j = 0; j < r_bytes; ++j) {
			vOut[j + numBlocks * uS] = uEncryptedCTR[sIvSize * 2 - r_bytes + j] ^ vIn[numBlocks * uS + j];
	}

	*psOutSize = sInSize;

	return sStatus;
}	

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
	uint16_t uM)
{
	izStatus sStatus = IZStatusSuccess;

	if (sIvSize != uM) {
		return IZStatusError;
	}
	if ((vIv == NULL) || (sIvSize == 0) || (uS == 0) || (uM == 0)) {
		return IZStatusInvalidParameter;
	}

	uint8_t r_bytes = sInSize % uS;
	uint32_t numBlocks = sInSize / uS;
	uint8_t uEncryptedOFB[sInSize];
	uint8_t uR[sIvSize];
	uint8_t uRBuff[uM - sBlockSize];
	memcpy(uR, vIv, sIvSize);

	for (uint32_t i = 0; i < numBlocks; ++i) {
		EncFunc(vKey, uR, uEncryptedOFB);
		for (uint16_t j = 0; j < uS; ++j) {
			vOut[j + i * uS] = uEncryptedOFB[sBlockSize - uS + j] ^ vIn[i * uS + j];
		}
		for (uint16_t c = sBlockSize; c < uM; ++c) {
			uRBuff[c - sBlockSize] = uR[c]; 
		}
		memcpy(uR, uRBuff, uM - sBlockSize);	
		memcpy(uR + uM - sBlockSize, uEncryptedOFB, sBlockSize);
	}	

	EncFunc(vKey, uR, uEncryptedOFB);	
	for (uint16_t j = 0; j < r_bytes; ++j) {
			vOut[j + numBlocks * uS] = uEncryptedOFB[sBlockSize - r_bytes + j] ^ vIn[numBlocks * uS + j];
	}

	*psOutSize = sInSize;

	return sStatus;
}	

	

static void izAddCTR8(uint8_t* uCTR, size_t sIvSize)
{
	uint64_t uBuffer = 0;

	memcpy(&uBuffer, uCTR, sIvSize * 2);
	uBuffer = izSwap64(uBuffer);
	uBuffer += 1;
	uBuffer = izSwap64(uBuffer);
	memcpy(uCTR, &uBuffer, sIvSize * 2);
}


static void IZPaddingX80(
	const uint8_t* vIn, 
	uint8_t* vOut, 
	size_t sBlockSize, 
	int r_bytes) 
{
	memcpy(vOut, vIn, r_bytes);
	vOut[r_bytes] = 0x80; // дополняем байтом 10000000
	for (int i = r_bytes + 1; i < sBlockSize; ++i) {
		vOut[i] = 0x00; // дополняем байтами 00000000
	}
}