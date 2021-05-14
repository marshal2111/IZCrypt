#ifndef SOURCE_H
#define SOURCE_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>	

#ifndef bool
typedef int bool;
#endif
#ifndef false
#define false 0x00
#endif
#ifndef true
#define true !false
#endif
#define MAGMA_BLOCK_SIZE 8


#endif //!SOURCE_H
