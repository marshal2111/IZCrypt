#ifndef IZMAGMA_H
#define IZMAGMA_H

#include "../../../include/IZCrypt.h"

/** @brief ���������� ������ ����� ��������� ����� 34.12-2015 n = 64
*
*	@param[in]  in		64-� ������ ���� �� ����
*	@param[in]	key		256-�� ������ ���� ��� ��������
*	@param[out]	out		64-x ������ ���� �� �����
*	@return ������ ��������
*/
void izMagmaEncrypt(uint8_t* key, uint8_t* in, uint8_t* out); //CHANGE RUTURN TO izStatus

/** @brief ������������� ������ ����� ��������� ����� 34.12-2015 n = 64
*
*	@param[in]  in		64-� ������ ���� �� ����
*	@param[in]	key		256-�� ������ ���� ��� ��������
*	@param[out]	out		64-x ������ ���� �� �����
*	@return ������ ��������
*/
void izMagmaDecrypt(uint8_t* key, uint8_t* in, uint8_t* out);

#endif //!IZMAGMA_H