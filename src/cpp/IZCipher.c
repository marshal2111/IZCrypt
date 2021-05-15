#include "../../include/IZCipher.h"
#include "../h/cipher/IZCipher_p.h"
#include "../h/cipher/IZMagma.h"
#include "../h/cipher/IZModes.h"

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
	izStatus sStatus = IZStatusSuccess;

	if ((cvIn == NULL) || (sInSize == 0) || 
			(cvKey == NULL) || (sKeySize == 0) || (vOut == NULL) || (psOutSize == NULL)) {
		sStatus = IZStatusInvalidParameter;
		return sStatus;
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
					sStatus = IZEncryptECB(&izMagmaEncrypt, cvKey, cvIn, sInSize, vOut, psOutSize, MAGMA_BLOCK_SIZE);
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
					sStatus = IZEncryptDecryptCTR(&izMagmaEncrypt, cvKey, cvIn, sInSize, vOut, psOutSize, MAGMA_BLOCK_SIZE, cvIv, psIvSize, FirstParam);

					break;
				case izIdCipherAlgorithmKyznechik:
					return IZStatusNotSupported;
			}
			break;

	} 
	return sStatus;
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
	izStatus sStatus = IZStatusSuccess;

	if ((cvIn == NULL) || (sInSize == 0) || 
			(cvKey == NULL) || (sKeySize == 0) || (vOut == NULL) || (psOutSize == NULL)) {
		sStatus = IZStatusInvalidParameter;
		return sStatus;
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
					sStatus = IZDecryptECB(&izMagmaEncrypt, cvKey, cvIn, sInSize, vOut, MAGMA_BLOCK_SIZE);
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
					sStatus = IZEncryptDecryptCTR(&izMagmaEncrypt, cvKey, cvIn, sInSize, vOut, psOutSize, MAGMA_BLOCK_SIZE, cvIv, psIvSize, FirstParam);

					break;
				case izIdCipherAlgorithmKyznechik:
					return IZStatusNotSupported;
			}
			break;

	} 
	return sStatus;
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