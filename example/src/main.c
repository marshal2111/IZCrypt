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
	
	const uint8_t ivSize = 19;
	const uint8_t a[19] = {
		0xfe, 0xdc, 0xba, 0x98,
		0x76, 0x54, 0x32, 0x10,
		0xfe, 0xdc, 0xba, 0x98,
		0x76, 0x54, 0x32, 0x10,
		0x54, 0x32, 0x10
	};

	printf("Vector value: ");
	for (int i = 0; i < ivSize; i++)
	{
		printf("%X ", a[i]);
	}
	printf("\n");

	uint8_t enc[ivSize];
	uint8_t dec[ivSize];
	size_t outSize = 0;
	izStatus status;	

	status = izEncrypt(izIdCipherAlgorithmMagma, izIdCipherModeECB, a, ivSize, key, 32, enc, &outSize);
	printf("status: %d\n", (uint8_t)status);
	status = izDecrypt(izIdCipherAlgorithmMagma, izIdCipherModeECB, enc, outSize, key, 32, dec, outSize);	

	printf("encrypted: "); 
	for (int i = 0; i < outSize; i++)
	{
		printf("%X ", enc[i]);
	}
	printf("\n");

	printf("decrypted: ");
	for (int i = 0; i < ivSize; i++)
	{
		printf("%X ", dec[i]);
	}
	printf("\n");
}