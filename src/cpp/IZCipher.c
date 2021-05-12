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
	// __in	const void* cvIv,
	// __in	size_t psIvSize,
	void* vOut,
	size_t* psOutSize)
{
	izStatus status = IZStatusSuccess;
	if (eMode = izIdCipherModeECB) {
		switch (eAlgorithm)
		{
			case izIdCipherAlgorithmMagma:
				status = IZEncryptECB(&izMagmaEncrypt, cvKey, cvIn, sInSize, vOut, 64);
				break;
		}
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
	// __in	const void* cvIv,
	// __in	size_t psIvSize,
	void* vOut,
	size_t* psOutSize)
{
	return IZStatusNotSupported;
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