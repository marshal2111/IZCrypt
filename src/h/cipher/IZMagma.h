#ifndef IZMAGMA_H
#define IZMAGMA_H

#include "../Source.h"

/** @brief Шифрование одного блока алгоримом Магма 34.12-2015 n = 64
*
*	@param[in]  in		64-х битный блок на вход
*	@param[in]	key		256-ти битный ключ для операции
*	@param[out]	out		64-x битный блок на выход
*/
void izMagmaEncrypt(uint8_t* key, const uint8_t* in, uint8_t* out);

/** @brief Расшифрование одного блока алгоримом Магма 34.12-2015 n = 64
*
*	@param[in]  in		64-х битный блок на вход
*	@param[in]	key		256-ти битный ключ для операции
*	@param[out]	out		64-x битный блок на выход
*/
void izMagmaDecrypt(uint8_t* key, const uint8_t* in, uint8_t* out);

#endif //!IZMAGMA_H