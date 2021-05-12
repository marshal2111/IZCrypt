#ifndef IZCIPHER_H
#define IZCIPHER_H

#include "../src/h/cipher/IZCipher_p.h"

/** @brief ��������� ���������� */
typedef enum izCipherAlgorithms_t {
	izIdCipherAlgorithmMagma,
	//izIdCipherAlgorithmKyznechik
} izCipherAlgorithms;

/** @brief ������ ���������� */
typedef enum izCipherMode_t {
	izIdCipherModeECB,
	// izIdCipherModeCTR,
	// izIdCipherModeOFB,
	// izIdCipherModeCBC,
	// izIdCipherModeCFB,
	// izIdCipherModeMAC
} izCipherMode;

/** @brief ���������� �������� �������� ������� "vIn" ������� "sInSize", 
*		��������� ��������� � �������� ������ "vOut" ��� ����������� ������� ��������� � "psOutSize".
*		�������� � ����� ���������� ����������� � ���������� "eAlgorithm", "eMode" ��������������.
*		��� ��������� ������� ���������� ���������� �������� ������ ������������� � "cvIv" �������� "psIvSize".
*		���� �������� "vOut" = null, �� � ��������� "psOutSize" ����� ������ ����������� ������ ������ ��� ���������� ������� "cvIn".
*		������� ������� � "psOutSize" ����������� ����������� ������������� ����.
* 
*	@param[in]		eAlgorithm	�������� ����������
*	@param[in]		eMode		����� ����������
*	@param[in]		cvIn		������� ������� ������
*	@param[in]		sInSize		������ �������� ������� (� ������)
*	@param[in]		cvKey		�������� ������� ������
*	@param[in]		sKeySize	������ ��������� ������� (� ������)
*	@param[in]		cvIv		������� ������ � �������� �������������
*	@param[in]		psIvSize	������ ������� ������������� (� ������)
*	@param[out]		vOut		�������� ������� ������
*	@param[in_out]	psOutSize	������ ��������� ������� (� ������)
*	@return ������ ��������
*/
izStatus izEncrypt(
	__in	izCipherAlgorithms eAlgorithm,
	__in	izCipherMode eMode,
	__in	const void* cvIn,
	__in	size_t sInSize,
	__in	const void* cvKey,
	__in	size_t sKeySize,
	// __in	const void* cvIv,
	// __in	size_t psIvSize,
	__out	void* vOut,
	__inout	size_t* psOutSize);

/** @brief ����������� �������� �������� ������� "vIn" ������� "sInSize",
*		��������� ��������� � �������� ������ "vOut" ��� ����������� ������� ��������� � "psOutSize".
*		�������� � ����� ���������� ����������� � ���������� "eAlgorithm", "eMode" ��������������.
*		��� ��������� ������� ���������� ���������� �������� ������ ������������� � "cvIv" �������� "psIvSize".
*		���� �������� "vOut" = null, �� � ��������� "psOutSize" ����� ������ ����������� ������ ������ ��� ���������� ������� "cvIn".
*
*	@param[in]		eAlgorithm	�������� ����������
*	@param[in]		eMode		����� ����������
*	@param[in]		cvIn		������� ������� ������
*	@param[in]		sInSize		������ �������� ������� (� ������)
*	@param[in]		cvKey		�������� ������� ������
*	@param[in]		sKeySize	������ ��������� ������� (� ������)
*	@param[in]		cvIv		������� ������ � �������� �������������
*	@param[in]		psIvSize	������ ������� ������������� (� ������)
*	@param[out]		vOut		�������� ������� ������
*	@param[in_out]	psOutSize	������ ��������� ������� (� ������)
*	@return ������ ��������
*/
izStatus izDecrypt(
	__in	izCipherAlgorithms eAlgorithm,
	__in	izCipherMode eMode,
	__in	const void* cvIn,
	__in	size_t sInSize,
	__in	const void* cvKey,
	__in	size_t sKeySize,
	// __in	const void* cvIv,
	// __in	size_t psIvSize,
	__out	void* vOut,
	__inout	size_t* psOutSize);

/** @brief ��������� ��� �������� ��������� ���������� */
typedef struct izEncryptionCtx_t izEncryptionCtx;

/** @brief ������������� ��������� ��� ��������� ����������
*
*	@param[in_out]	sCtx	�������� ����������
*	@return ������ ��������
*/
izStatus izEncryptionCtxInit(
	__inout izEncryptionCtx* sCtx);

/** @brief ������� ��������� ����������
*
*	@param[in_out]	sCtx	�������� ����������
*	@return ������ ��������
*/
izStatus izEncryptionCtxFree(
	__in izEncryptionCtx* sCtx);

/** @brief ����� ���������� (����������� ���������� ��������)*/
typedef enum izCipherPropertyName_t {
	izCipherPropertyAlgorithm,
	izCipherPropertyMode
} izCipherPropertyName;

/** @brief ��������� ���������� � ��������
*
*	@param[in_out]	sCtx			��������
*	@param[in]		ePropertyKey	���� ���������
*	@param[in]		strValue		������������� �������� ���������
*	@return ������ ��������
*/
izStatus izEncryptionSetProperty(
	__inout	izEncryptionCtx			sCtx, 
	__in	izCipherPropertyName	ePropertyKey,
	__in	const char*				strValue);

/** @brief ����� ���������� (������� �������) */
typedef enum izCipherPropertyByteVectorName_t {
	izCipherPropertyIV,
	izCipherPropertyKey
} izCipherPropertyByteVectorName;

/** @brief ��������� ���������� � ��������
*
*	@param[in_out]	sCtx			��������
*	@param[in]		ePropertyKey	���� ���������
*	@param[in]		cvValue			������� ������ - �������� ���������
*	@return ������ ��������
*/
izStatus izEncryptionSetPropertyByteVector(
	__inout	izEncryptionCtx					sCtx,
	__in	izCipherPropertyByteVectorName	ePropertyKey,
	__in	const void*						cvValue);

/** @brief �������� ���������� �������� ����� "cvIn", ���������� ���������� ����� �������������� �� �����.
*		���� ����� ������� � �������� � ��������� ������� ����������� �� ���������� izEncryptionUpdate().
*		���� �������� "vOut"=null, � �������� "psOutSize" ����� ������� ������ ������� ����������� ��� ��������� ��������� ��������.
*		������� ���������� � "psOutSize" ����������� ����������� ������������� ����.
* 
*	@param[in]		sCtx		�������� ����������
*	@param[in]		cvIn		������� ������� ������
*	@param[in]		sInSize		������ �������� ������� (� ������)
*	@param[out]		vOut		�������� ������� ������
*	@param[in_out]	psOutSize	������ ��������� ������� (� ������)
*	@return ������ ��������
*/
izStatus izEncryptionUpdate(
	__in	izEncryptionCtx	sCtx,
	__in	const void*		cvIn,
	__in	size_t			sInSize,
	__out	void*			vOut,
	__inout	size_t*			psOutSize);

/** @brief ����������� Update ��������� ����������. ��������� ���� ����� �� ������������� �������� �� ������� ����� � ����������.
*		���� �������� "vOut"=null, � �������� "psOutSize" ����� ������� ������ ������� ����������� ��� ��������� ��������� ��������.
*		������� ���������� � "psOutSize" ����������� ����������� ������������� ����.
*
*	@param[in]		sCtx		�������� ����������
*	@param[in]		cvIn		������� ������� ������
*	@param[in]		sInSize		������ �������� ������� (� ������)
*	@param[out]		vOut		�������� ������� ������
*	@param[in_out]	psOutSize	������ ��������� ������� (� ������)
*	@return ������ ��������
*/
izStatus izEncryptionFinalUpdate(__in	izEncryptionCtx sCtx,
	__in	const void*	cvIn,
	__in	size_t		sInSize,
	__out	void*		vOut,
	__inout	size_t*		psOutSize);

#endif //!IZCIPHER_H