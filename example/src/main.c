#include "IZCrypt.h"
#include <stdio.h>
#include <inttypes.h>
#include <sys/stat.h>

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

	FILE* fp = fopen("../src/picture.jpg", "r");

	if (fp == NULL) {
        printf("File Not Found!\n");
        return -1;
    }

    /***Считываем данные из файла***/
	fseek(fp, 0L, SEEK_END);
	long int FileSize = ftell(fp);
	rewind(fp);

	uint8_t* vIn = malloc(FileSize * sizeof(uint8_t));
	fread(vIn, 1, FileSize, fp);
	/*******************************/

	/***Данные инициализации для CTR***/
	const uint8_t uIv[4] = {
		0x12, 0x34, 0x56, 0x78
	};
	size_t sIvSize = 4;
	uint8_t uS = 8;
	/*********************************/

	uint8_t* enc = malloc((FileSize + 1) * sizeof(uint8_t));	
	size_t outSize = 0;
	izStatus status;	

	/***Зашифрование данных***/
	status = izEncrypt(izIdCipherAlgorithmMagma, izIdCipherModeCTR, vIn, FileSize, key, 32, uIv, sIvSize, uS, 0, enc, &outSize);
	
	printf("Status of encryption: %d\n", (uint8_t)status);
	
	if (status != IZStatusSuccess) {
		printf("ENCRYPTION FAILED\n");
		free(enc);
		free(vIn);
		return -1;
	}

	fp = fopen("../src/picture_encrypted", "w");
	fwrite(enc, 1, outSize, fp);
	fclose(fp);
	/*************************/

	uint8_t* dec = malloc(outSize * sizeof(uint8_t));

	/***Расшифрование данных***/
	status = izDecrypt(izIdCipherAlgorithmMagma, izIdCipherModeCTR, enc, outSize, key, 32, uIv, sIvSize, uS, 0, dec, &outSize);	

	if (status != IZStatusSuccess) {
		printf("DECRYPTION FAILED\n");
		free(enc);
		free(vIn);
		free(dec);
		return -1;
	}

	printf("Status of decryption: %d\n", (uint8_t)status);
	fp = fopen("../src/picture_decrypted.jpg", "w");
	fwrite(dec, 1, outSize, fp);
	fclose(fp);
	/*************************/


	/*Высвобождение памяти*/
	free(enc);
	free(dec);
	free(vIn);
	/**********************/
}