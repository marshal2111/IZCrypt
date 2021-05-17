#include "IZCrypt.h"
#include <stdio.h>
#include <inttypes.h>

int main(int argc, char *argv[])
{
	uint8_t key[32] = {
		0xff, 0xee, 0xdd, 0xcc, 
		0xbb, 0xaa, 0x99, 0x88, 
		0x77, 0x66, 0x55, 0x44, 
		0x33, 0x22, 0x11, 0x00, 
		0xf0, 0xf1, 0xf2, 0xf3, 
		0xf4, 0xf5, 0xf6, 0xf7, 
		0xf8, 0xf9, 0xfa, 0xfb, 
		0xfc, 0xfd, 0xfe, 0xff

	};

	const uint8_t inSize = 32;
	const uint8_t a[32] = {
		0xfe, 0xdc, 0xba, 0x98,
		0x76, 0x54, 0x32, 0x10,
		0x80, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x54, 0x32, 0x10, 0xfa,
		0x76, 0x54, 0x32, 0x10,
		0x80, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
	};

	const uint8_t uIv[4] = {
		0x12, 0x34, 0x56, 0x78
	};
	size_t sIvSize = 4;
	uint8_t uS = 8;

	printf("Vector value: ");
	for (int i = 0; i < inSize; i++)
	{
		printf("%X ", a[i]);
	}
	printf("\n");

	uint8_t enc[inSize + 8];

	size_t outSize = 0;
	izStatus status;		

	status = izEncrypt(izIdCipherAlgorithmMagma, izIdCipherModeCTR, a, inSize, key, 32, uIv, sIvSize, uS, 0, enc, &outSize);

	printf("status: %d\n", (uint8_t)status);
	printf("encrypted %d: ", outSize); 
	for (int i = 0; i < outSize; i++)
	{
		printf("%X ", enc[i]);
	}
	printf("\n");

	uint8_t dec[outSize];
	status = izDecrypt(izIdCipherAlgorithmMagma, izIdCipherModeCTR, enc, outSize, key, 32, uIv, sIvSize, uS, 0, dec, &outSize);	

	printf("status: %d\n", (uint8_t)status);
	printf("decrypted: ");
	for (int i = 0; i < outSize; i++)
	{
		printf("%X ", dec[i]);
	}
	printf("\n");
}