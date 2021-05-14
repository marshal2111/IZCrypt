#include "../../include/IZCipher.h"
#include "../h/cipher/IZCipher_p.h"
#include "../h/cipher/IZMagma.h"

izStatus izEncrypt(
	izCipherAlgorithms eAlgorithm,
	izCipherMode eMode,
	const void* cvIn,
	size_t sInSize,
	const void* cvKey,
	size_t sKeySize,
	const void* cvIv,
	size_t psIvSize,
	uint16_t FirstParam,
	uint16_t SecondParam,
	void* vOut,
	size_t* psOutSize)
{
	izStatus status = IZStatusSuccess;

	if ((cvIn == NULL) || (sInSize == 0) || 
			(cvKey == NULL) || (sKeySize == 0) || (vOut == NULL) || (psOutSize == NULL)) {
		status = IZStatusInvalidParameter;
		return status;
	}

	switch (eMode) 
	{
		case izIdCipherModeECB:
			switch (eAlgorithm)
			{
				case izIdCipherAlgorithmMagma:
					if (sKeySize != 32) {
						return IZStatusInvalidParameter;
					}
					status = IZEncryptECB(&izMagmaEncrypt, cvKey, cvIn, sInSize, vOut, psOutSize, MAGMA_BLOCK_SIZE);
					break;
				case izIdCipherAlgorithmKyznechik:
					return IZStatusNotSupported;
			}
			break;
		case izIdCipherModeCTR:
			switch (eAlgorithm)
			{
				case izIdCipherAlgorithmMagma:
					if (sKeySize != 32) {
						return IZStatusInvalidParameter;
					}
					status = IZEncryptCTR(&izMagmaEncrypt, cvKey, cvIn, sInSize, vOut, psOutSize, MAGMA_BLOCK_SIZE, 8);
					break;
				case izIdCipherAlgorithmKyznechik:
					return IZStatusNotSupported;
			}
			break;

	} 
	return status;
}

izStatus izDecrypt(
	izCipherAlgorithms eAlgorithm,
	izCipherMode eMode,
	const void* cvIn,
	size_t sInSize,
	const void* cvKey,
	size_t sKeySize,
	const void* cvIv,
	size_t psIvSize,
	uint16_t FirstParam,
	uint16_t SecondParam,
	void* vOut,
	size_t* psOutSize)
{
	izStatus status = IZStatusSuccess;
	if (eMode == izIdCipherModeECB) {
		switch (eAlgorithm)
		{
			case izIdCipherAlgorithmMagma:
				status = IZDecryptECB(&izMagmaDecrypt, cvKey, cvIn, sInSize, vOut, MAGMA_BLOCK_SIZE);
				break;
		}
	} 
	return status;
}

// izStatus izEncryptionCtxInit(
// 	__inout izEncryptionCtx* sCtx)
// {
// 	return IZStatusNotSupported;
// }

// izStatus izEncryptionCtxFree(
// 	__in izEncryptionCtx* sCtx)
// {
// 	return IZStatusNotSupported;
// }

// izStatus izEncryptionSetProperty(
// 	__inout	izEncryptionCtx			sCtx,
// 	__in	izCipherPropertyName	ePropertyKey,
// 	__in	const char* strValue)
// {
// 	return IZStatusNotSupported;
// }

// izStatus izEncryptionSetPropertyByteVector(
// 	__inout	izEncryptionCtx					sCtx,
// 	__in	izCipherPropertyByteVectorName	ePropertyKey,
// 	__in	const void* cvValue)
// {
// 	return IZStatusNotSupported;
// }

// izStatus izEncryptionUpdate(
// 	__in	izEncryptionCtx	sCtx,
// 	__in	const void* cvIn,
// 	__in	size_t			sInSize,
// 	__out	void* vOut,
// 	__inout	size_t* psOutSize)
// {
// 	return IZStatusNotSupported;
// }

// izStatus izEncryptionFinalUpdate(__in	izEncryptionCtx sCtx,
// 	__in	const void* cvIn,
// 	__in	size_t		sInSize,
// 	__out	void* vOut,
// 	__inout	size_t* psOutSize)
// {
// 	return IZStatusNotSupported;
// }