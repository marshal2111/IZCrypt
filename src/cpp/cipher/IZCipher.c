#include "../../../include/IZCipher.h"
#include "../../h/cipher/IZCipher_p.h"

izStatus izEncrypt(
	__in	izCipherAlgorithms eAlgorithm,
	__in	izCipherMode eMode,
	__in	const void* cvIn,
	__in	size_t sInSize,
	__in	const void* cvKey,
	__in	size_t sKeySize,
	__in	const void* cvIv,
	__in	size_t psIvSize,
	__out	void* vOut,
	__inout	size_t* psOutSize)
{
	return IZStatusNotSupported;
}

izStatus izDecrypt(
	__in	izCipherAlgorithms eAlgorithm,
	__in	izCipherMode eMode,
	__in	const void* cvIn,
	__in	size_t sInSize,
	__in	const void* cvKey,
	__in	size_t sKeySize,
	__in	const void* cvIv,
	__in	size_t psIvSize,
	__out	void* vOut,
	__inout	size_t* psOutSize)
{
	return IZStatusNotSupported;
}

izStatus izEncryptionCtxInit(
	__inout izEncryptionCtx* sCtx)
{
	return IZStatusNotSupported;
}

izStatus izEncryptionCtxFree(
	__in izEncryptionCtx* sCtx)
{
	return IZStatusNotSupported;
}

izStatus izEncryptionSetProperty(
	__inout	izEncryptionCtx			sCtx,
	__in	izCipherPropertyName	ePropertyKey,
	__in	const char* strValue)
{
	return IZStatusNotSupported;
}

izStatus izEncryptionSetPropertyByteVector(
	__inout	izEncryptionCtx					sCtx,
	__in	izCipherPropertyByteVectorName	ePropertyKey,
	__in	const void* cvValue)
{
	return IZStatusNotSupported;
}

izStatus izEncryptionUpdate(
	__in	izEncryptionCtx	sCtx,
	__in	const void* cvIn,
	__in	size_t			sInSize,
	__out	void* vOut,
	__inout	size_t* psOutSize)
{
	return IZStatusNotSupported;
}

izStatus izEncryptionFinalUpdate(__in	izEncryptionCtx sCtx,
	__in	const void* cvIn,
	__in	size_t		sInSize,
	__out	void* vOut,
	__inout	size_t* psOutSize)
{
	return IZStatusNotSupported;
}