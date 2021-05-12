#ifndef IZCIPHER_H
#define IZCIPHER_H

#include "../src/h/cipher/IZCipher_p.h"

/** @brief Алгоритмы шифрования */
typedef enum izCipherAlgorithms_t {
	izIdCipherAlgorithmMagma,
	//izIdCipherAlgorithmKyznechik
} izCipherAlgorithms;

/** @brief Режимы шифрования */
typedef enum izCipherMode_t {
	izIdCipherModeECB,
	// izIdCipherModeCTR,
	// izIdCipherModeOFB,
	// izIdCipherModeCBC,
	// izIdCipherModeCFB,
	// izIdCipherModeMAC
} izCipherMode;

/** @brief Шифрование входного битового вектора "vIn" размера "sInSize", 
*		результат запишется в выходной буффер "vOut" при достаточном размере указанном в "psOutSize".
*		Алгоритм и режим шифрования указывается в параметрах "eAlgorithm", "eMode" соответственно.
*		Для некоторых режимов шифрования необходимо передать вектор инициализации в "cvIv" размером "psIvSize".
*		Если параметр "vOut" = null, то в параметре "psOutSize" будет указан необходимый размер буфера для шифрования вектора "cvIn".
*		Фукнция запишет в "psOutSize" фактическое колличество зашифрованных байт.
* 
*	@param[in]		eAlgorithm	Алгоритм шифрования
*	@param[in]		eMode		Режим шифрования
*	@param[in]		cvIn		Входной битовый вектор
*	@param[in]		sInSize		Размер входного вектора (в байтах)
*	@param[in]		cvKey		Ключевой битовый вектор
*	@param[in]		sKeySize	Размер ключевого вектора (в байтах)
*	@param[in]		cvIv		Битовый вектор с вектором инициализации
*	@param[in]		psIvSize	Размер вектора инициализации (в байтах)
*	@param[out]		vOut		Выходной битовый вектор
*	@param[in_out]	psOutSize	Размер выходного вектора (в байтах)
*	@return Статус операции
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

/** @brief Расфрование входного битового вектора "vIn" размера "sInSize",
*		результат запишется в выходной буффер "vOut" при достаточном размере указанном в "psOutSize".
*		Алгоритм и режим шифрования указывается в параметрах "eAlgorithm", "eMode" соответственно.
*		Для некоторых режимов шифрования необходимо передать вектор инициализации в "cvIv" размером "psIvSize".
*		Если параметр "vOut" = null, то в параметре "psOutSize" будет указан необходимый размер буфера для шифрования вектора "cvIn".
*
*	@param[in]		eAlgorithm	Алгоритм шифрования
*	@param[in]		eMode		Режим шифрования
*	@param[in]		cvIn		Входной битовый вектор
*	@param[in]		sInSize		Размер входного вектора (в байтах)
*	@param[in]		cvKey		Ключевой битовый вектор
*	@param[in]		sKeySize	Размер ключевого вектора (в байтах)
*	@param[in]		cvIv		Битовый вектор с вектором инициализации
*	@param[in]		psIvSize	Размер вектора инициализации (в байтах)
*	@param[out]		vOut		Выходной битовый вектор
*	@param[in_out]	psOutSize	Размер выходного вектора (в байтах)
*	@return Статус операции
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

// * @brief Структура для хранения контекста шифрования 
// typedef struct izEncryptionCtx_t izEncryptionCtx;

/** @brief Инициализация контекста для поточного шифрования
*
*	@param[in_out]	sCtx	Контекст шифрования
*	@return Статус операции
*/
// izStatus izEncryptionCtxInit(
// 	_In_out izEncryptionCtx* sCtx);

// /** @brief Очистка контекста шифрования
// *
// *	@param[in_out]	sCtx	Контекст шифрования
// *	@return Статус операции
// */
// izStatus izEncryptionCtxFree(
// 	_In_ izEncryptionCtx* sCtx);

// /** @brief Ключи параметров (Принимающих конктерное значение)*/
// typedef enum izCipherPropertyName_t {
// 	izCipherPropertyAlgorithm,
// 	izCipherPropertyMode
// } izCipherPropertyName;

// /** @brief Установка параметров в контекст
// *
// *	@param[in_out]	sCtx			Контекст
// *	@param[in]		ePropertyKey	Ключ параметра
// *	@param[in]		strValue		Идентификатор значения параметра
// *	@return Статус операции
// */
// izStatus izEncryptionSetProperty(
// 	_In_out	izEncryptionCtx			sCtx, 
// 	_In_	izCipherPropertyName	ePropertyKey,
// 	_In_	const char*				strValue);

// /** @brief Ключи параметров (Битовые вектора) */
// typedef enum izCipherPropertyByteVectorName_t {
// 	izCipherPropertyIV,
// 	izCipherPropertyKey
// } izCipherPropertyByteVectorName;

// /** @brief Установка параметров в контекст
// *
// *	@param[in_out]	sCtx			Контекст
// *	@param[in]		ePropertyKey	Ключ параметра
// *	@param[in]		cvValue			Битовый вектор - значение параметра
// *	@return Статус операции
// */
// izStatus izEncryptionSetPropertyByteVector(
// 	_In_out	izEncryptionCtx					sCtx,
// 	_In_	izCipherPropertyByteVectorName	ePropertyKey,
// 	_In_	const void*						cvValue);

// * @brief Поточное шифрование входного блока "cvIn", дополнение последнего блока осуществляться не будет.
// *		Блок будет сохранён и добавлен к следующем вектору полученному из следующего izEncryptionUpdate().
// *		Если параметр "vOut"=null, в параметр "psOutSize" будет записан размер массива необходимый для получения выходного значения.
// *		Функция записывает в "psOutSize" фактическое колличество зашифрованных байт.
// * 
// *	@param[in]		sCtx		Контекст шифрования
// *	@param[in]		cvIn		Входной битовый вектор
// *	@param[in]		sInSize		Размер входного вектора (в байтах)
// *	@param[out]		vOut		Выходной битовый вектор
// *	@param[in_out]	psOutSize	Размер выходного вектора (в байтах)
// *	@return Статус операции

// izStatus izEncryptionUpdate(
// 	_In_	izEncryptionCtx	sCtx,
// 	_In_	const void*		cvIn,
// 	_In_	size_t			sInSize,
// 	__out	void*			vOut,
// 	_In_out	size_t*			psOutSize);

// /** @brief Завершаюший Update поточного шифрования. Последний блок будет по необходимости дополнен до полного блока и зашифрован.
// *		Если параметр "vOut"=null, в параметр "psOutSize" будет записан размер массива необходимый для получения выходного значения.
// *		Функция записывает в "psOutSize" фактическое колличество зашифрованных байт.
// *
// *	@param[in]		sCtx		Контекст шифрования
// *	@param[in]		cvIn		Входной битовый вектор
// *	@param[in]		sInSize		Размер входного вектора (в байтах)
// *	@param[out]		vOut		Выходной битовый вектор
// *	@param[in_out]	psOutSize	Размер выходного вектора (в байтах)
// *	@return Статус операции
// */
// izStatus izEncryptionFinalUpdate(_In_	izEncryptionCtx sCtx,
// 	_In_	const void*	cvIn,
// 	_In_	size_t		sInSize,
// 	__out	void*		vOut,
// 	_In_out	size_t*		psOutSize);

#endif //!IZCIPHER_H