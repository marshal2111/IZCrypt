#ifndef IZCIPHER_H
#define IZCIPHER_H

#include <inttypes.h>
#include <stddef.h>
#include "IZStatus.h"

/** @brief Алгоритмы шифрования */
typedef enum izCipherAlgorithms_t {
	izIdCipherAlgorithmMagma,
	izIdCipherAlgorithmKyznechik
} izCipherAlgorithms;

/** @brief Режимы шифрования */
typedef enum izCipherMode_t {
	izIdCipherModeECB,
	izIdCipherModeCTR,
	// izIdCipherModeOFB,
	// izIdCipherModeCBC,
	// izIdCipherModeCFB,
	// izIdCipherModeMAC
} izCipherMode;

/** @brief Шифрование входного битового вектора "vIn" размера "sInSize", 
*		результат запишется в выходной буффер "vOut" при достаточном размере указанном в "psOutSize".
*		Алгоритм и режим шифрования указывается в параметрах "eAlgorithm", "eMode" соответственно.
*		Для некоторых режимов шифрования необходимо передать вектор инициализации в "cvIv" размером "psIvSize", а так же дополнительные параметры..
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
*	@param[in]		FirstParam	Первый параметр режима шифрования (если необходим)
*	@param[in]		SecondParam	Второй параметр режима шифрования (если необходим)
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
	const void* cvIv,
	size_t psIvSize,
	uint16_t FirstParam,
	uint16_t SecondParam,
	void* vOut,
	size_t* psOutSize);

/** @brief Расфрование входного битового вектора "vIn" размера "sInSize",
*		результат запишется в выходной буффер "vOut" при достаточном размере указанном в "psOutSize".
*		Алгоритм и режим шифрования указывается в параметрах "eAlgorithm", "eMode" соответственно.
*		Для некоторых режимов шифрования необходимо передать вектор инициализации в "cvIv" размером "psIvSize", а так же дополнительные параметры.
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
*	@param[in]		FirstParam 	Первый параметр режима шифрования (если необходим)
*	@param[in]		FirstParam 	Второй параметр режима шифрования (если необходим)
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
	const void* cvIv,
	size_t psIvSize,
	uint16_t FirstParam,
	uint16_t SecondParam,
	void* vOut,
	size_t* psOutSize);

#endif //!IZCIPHER_H