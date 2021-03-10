#ifndef TNMAGMA_H
#define TNMAGMA_H

#include "..\..\src\h\cipher\TNpMagma.h"

/** @brief ���������� ������ ����� ��������� ����� 34.12-2015 n = 64
*
*	@param[in]  in		64-� ������ ���� �� ����
*	@param[in]	key		256-�� ������ ���� ��� ��������
*	@param[out]	out		64-x ������ ���� �� �����
*	@return ������ ��������
*/
tnStatus tnEncryptBlock(uint8_t* in, uint8_t* key, uint8_t* out);

/** @brief ������������� ������ ����� ��������� ����� 34.12-2015 n = 64
*
*	@param[in]  in		64-� ������ ���� �� ����
*	@param[in]	key		256-�� ������ ���� ��� ��������
*	@param[out]	out		64-x ������ ���� �� �����
*	@return ������ ��������
*/
tnStatus tnDecryptBlock(uint8_t* in, uint8_t* key, uint8_t* out);

#endif //!TNMAGMA_H