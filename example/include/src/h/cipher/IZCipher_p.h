#ifndef IZPCIPHER_H
#define IZPCIPHER_H

#include "../Source.h"
#include "../../../include/IZStatus.h"

struct izEncryptionCtx_t {
	uint8_t* initializationVector;
	size_t initializationVectorSize;
};

#endif //!IZPCIPHER_H