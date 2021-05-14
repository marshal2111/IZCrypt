#ifndef IZSTATUS_H
#define IZSTATUS_H

typedef enum izStatus_t {
	IZStatusSuccess\
		= 0x00000000,
	IZStatusError\
		= 0x80000000,
	IZStatusInvalidParameter\
		= 0x80000001,
	IZStatusNotSupported\
		= 0x80000002
} izStatus;

#endif //!IZSTATUS_H