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
	izCipherAlgorithms eAlgorithm,
	izCipherMode eMode,
	const void* cvIn,
	size_t sInSize,
	const void* cvKey,
	size_t sKeySize,
	// const void* cvIv,
	// size_t psIvSize,
	void* vOut,
	size_t* psOutSize);

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
	izCipherAlgorithms eAlgorithm,
	izCipherMode eMode,
	const void* cvIn,
	size_t sInSize,
	const void* cvKey,
	size_t sKeySize,
	// _In_	const void* cvIv,
	// _In_	size_t psIvSize,
	void* vOut,
	size_t* psOutSize);

// * @brief ��������� ��� �������� ��������� ���������� 
// typedef struct izEncryptionCtx_t izEncryptionCtx;

/** @brief ������������� ��������� ��� ��������� ����������
*
*	@param[in_out]	sCtx	�������� ����������
*	@return ������ ��������
*/
// izStatus izEncryptionCtxInit(
// 	_In_out izEncryptionCtx* sCtx);

// /** @brief ������� ��������� ����������
// *
// *	@param[in_out]	sCtx	�������� ����������
// *	@return ������ ��������
// */
// izStatus izEncryptionCtxFree(
// 	_In_ izEncryptionCtx* sCtx);

// /** @brief ����� ���������� (����������� ���������� ��������)*/
// typedef enum izCipherPropertyName_t {
// 	izCipherPropertyAlgorithm,
// 	izCipherPropertyMode
// } izCipherPropertyName;

// /** @brief ��������� ���������� � ��������
// *
// *	@param[in_out]	sCtx			��������
// *	@param[in]		ePropertyKey	���� ���������
// *	@param[in]		strValue		������������� �������� ���������
// *	@return ������ ��������
// */
// izStatus izEncryptionSetProperty(
// 	_In_out	izEncryptionCtx			sCtx, 
// 	_In_	izCipherPropertyName	ePropertyKey,
// 	_In_	const char*				strValue);

// /** @brief ����� ���������� (������� �������) */
// typedef enum izCipherPropertyByteVectorName_t {
// 	izCipherPropertyIV,
// 	izCipherPropertyKey
// } izCipherPropertyByteVectorName;

// /** @brief ��������� ���������� � ��������
// *
// *	@param[in_out]	sCtx			��������
// *	@param[in]		ePropertyKey	���� ���������
// *	@param[in]		cvValue			������� ������ - �������� ���������
// *	@return ������ ��������
// */
// izStatus izEncryptionSetPropertyByteVector(
// 	_In_out	izEncryptionCtx					sCtx,
// 	_In_	izCipherPropertyByteVectorName	ePropertyKey,
// 	_In_	const void*						cvValue);

// * @brief �������� ���������� �������� ����� "cvIn", ���������� ���������� ����� �������������� �� �����.
// *		���� ����� ������� � �������� � ��������� ������� ����������� �� ���������� izEncryptionUpdate().
// *		���� �������� "vOut"=null, � �������� "psOutSize" ����� ������� ������ ������� ����������� ��� ��������� ��������� ��������.
// *		������� ���������� � "psOutSize" ����������� ����������� ������������� ����.
// * 
// *	@param[in]		sCtx		�������� ����������
// *	@param[in]		cvIn		������� ������� ������
// *	@param[in]		sInSize		������ �������� ������� (� ������)
// *	@param[out]		vOut		�������� ������� ������
// *	@param[in_out]	psOutSize	������ ��������� ������� (� ������)
// *	@return ������ ��������

// izStatus izEncryptionUpdate(
// 	_In_	izEncryptionCtx	sCtx,
// 	_In_	const void*		cvIn,
// 	_In_	size_t			sInSize,
// 	__out	void*			vOut,
// 	_In_out	size_t*			psOutSize);

// /** @brief ����������� Update ��������� ����������. ��������� ���� ����� �� ������������� �������� �� ������� ����� � ����������.
// *		���� �������� "vOut"=null, � �������� "psOutSize" ����� ������� ������ ������� ����������� ��� ��������� ��������� ��������.
// *		������� ���������� � "psOutSize" ����������� ����������� ������������� ����.
// *
// *	@param[in]		sCtx		�������� ����������
// *	@param[in]		cvIn		������� ������� ������
// *	@param[in]		sInSize		������ �������� ������� (� ������)
// *	@param[out]		vOut		�������� ������� ������
// *	@param[in_out]	psOutSize	������ ��������� ������� (� ������)
// *	@return ������ ��������
// */
// izStatus izEncryptionFinalUpdate(_In_	izEncryptionCtx sCtx,
// 	_In_	const void*	cvIn,
// 	_In_	size_t		sInSize,
// 	__out	void*		vOut,
// 	_In_out	size_t*		psOutSize);

#endif //!IZCIPHER_H