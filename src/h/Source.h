#ifndef SOURCE_H
#define SOURCE_H

#define __STDC_WANT_LIB_EXT1__ 1

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <inttypes.h>
#include <memory.h>
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


#endif //!SOURCE_H
