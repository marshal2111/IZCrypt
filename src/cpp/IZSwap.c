#include "../h/cipher/IZSwap.h"

uint64_t izSwap64(uint64_t a)
{
	uint64_t middle = (uint64_t)(izSwap32((a & 0x0000FFFFFFFF0000) >> 16)) << 16;
	uint64_t head = (uint64_t)(izSwap16(a & 0x000000000000FFFF)) << 48;
	uint64_t tail =(uint64_t)(izSwap16((a & 0xFFFF000000000000) >> 48));
	return head | middle | tail;
}

uint32_t izSwap32(uint32_t a)
{
	return ((a << 24) & 0xFF000000)| ((a >> 8) & 0x0000FF00) | ((a << 8) & 0x00FF0000) | ((a >> 24) & 0x000000FF);
}

uint16_t izSwap16(uint16_t a)
{
	return ((a << 8) & 0xFF00) | ((a >> 8) & 0x00FF);
}
