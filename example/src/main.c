#include "IZCrypt.h"
#include <stdio.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/time.h>

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

	/***Инициализация парамтеров***/
	const uint8_t uIv[4] = {
		0x12, 0x34, 0x56, 0x78
	};
	size_t sIvSize = 4;
	uint8_t uS = 8;
	size_t outSize = 0;
	izStatus status;
	/******************************/
	
		
	/***Зашифрование данных***/
	uint8_t* enc = malloc((FileSize + 1) * sizeof(uint8_t));

	struct timeval begin, end;
    gettimeofday(&begin, 0);

	status = izEncrypt(izIdCipherAlgorithmMagma, izIdCipherModeECB, vIn, FileSize, key, 32, uIv, sIvSize, uS, 0, enc, &outSize);

	gettimeofday(&end, 0);
    long seconds = end.tv_sec - begin.tv_sec;
    long microseconds = end.tv_usec - begin.tv_usec;
    double elapsed = seconds + microseconds*1e-6;

	printf("Status of encryption: %d\n", (uint8_t)status);
	
	if (status != IZStatusSuccess) {
		printf("ENCRYPTION FAILED\n");
		free(enc);
		free(vIn);
		return -1;
	}

	printf("Time of encryption: %.3f seconds.\n", elapsed);

	fp = fopen("../src/picture_encrypted", "w");
	fwrite(enc, 1, outSize, fp);
	fclose(fp);
	/*************************/


	/***Расшифрование данных***/
	uint8_t* dec = malloc(outSize * sizeof(uint8_t));

	gettimeofday(&begin, 0);

	status = izDecrypt(izIdCipherAlgorithmMagma, izIdCipherModeECB, enc, outSize, key, 32, uIv, sIvSize, uS, 0, dec, &outSize);	

	gettimeofday(&end, 0);
	seconds = end.tv_sec - begin.tv_sec;
    microseconds = end.tv_usec - begin.tv_usec;
    elapsed = seconds + microseconds*1e-6;

    printf("Status of decryption: %d\n", (uint8_t)status);

	if (status != IZStatusSuccess) {
		printf("DECRYPTION FAILED\n");
		free(enc);
		free(vIn);
		free(dec);
		return -1;
	}

	printf("Time of decryption: %.3f seconds.\n", elapsed);

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