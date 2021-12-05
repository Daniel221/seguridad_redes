// proyecto_cripto.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include "sodium.h"
#include <iostream>

bool cipherFile(const char* textFileName,  unsigned char* key, unsigned char* nonce) {
	FILE * fplaintext;
	FILE * fciphertext;

	errno_t ferr = fopen_s(&fplaintext, textFileName, "rb");
	fseek(fplaintext, 0, SEEK_END);
	long plain_text_len = ftell(fplaintext);
	fseek(fplaintext, 0, SEEK_SET);
	unsigned char *plain_text = (unsigned char *)malloc(plain_text_len + 1);
	fread(plain_text, 1, plain_text_len, fplaintext);
	fclose(fplaintext);

	unsigned char* cipher_text = new unsigned char[plain_text_len];
	int errorcode = crypto_stream_chacha20_xor(cipher_text, plain_text, plain_text_len, nonce, key);

	char aux[40];

	strcpy_s(aux, 40, "c_");
	strcat_s(aux, 40, textFileName);

	ferr = fopen_s(&fciphertext, aux, "wb");
	fwrite(cipher_text, 1, plain_text_len, fciphertext);
	fclose(fciphertext);

	printf("\n-I- El archivo se ha cifrado\n\n");

	return true;
}

bool decipherFile(const char* textFileName,  unsigned char* key, unsigned char* nonce) {
	FILE* fciphertext;
	FILE* fdeciphertext;

	errno_t ferr = fopen_s(&fciphertext, textFileName, "rb");
	fseek(fciphertext, 0, SEEK_END);
	long cipher_text_len = ftell(fciphertext);
	fseek(fciphertext, 0, SEEK_SET);
	unsigned char *cipher_text = (unsigned char *)malloc(cipher_text_len + 1);
	fread(cipher_text, 1, cipher_text_len, fciphertext);
	fclose(fciphertext);

	unsigned char* decipher_text = new unsigned char[cipher_text_len];
	int errorcode = crypto_stream_chacha20_xor(decipher_text, cipher_text, cipher_text_len, nonce, key);

	char aux[40];

	strcpy_s(aux, 40, "dc_");
	strcat_s(aux, 40, textFileName);

	ferr = fopen_s(&fdeciphertext, aux, "wb");
	fwrite(decipher_text, 1, cipher_text_len, fdeciphertext);
	fclose(fdeciphertext);

	printf("-I- Archivo decifrado\n\n");

	return true;
}

bool signFile(const char* fileName, unsigned char* sk) {
	FILE * fplaintext;

	errno_t ferr = fopen_s(&fplaintext, fileName, "rb");
	fseek(fplaintext, 0, SEEK_END);
	long msg_len = ftell(fplaintext);
	fseek(fplaintext, 0, SEEK_SET);
	unsigned char *msg = (unsigned char *)malloc(msg_len + 1);
	fread(msg, 1, msg_len, fplaintext);
	fclose(fplaintext);

	unsigned char sig[crypto_sign_BYTES];

	crypto_sign_detached(sig, NULL, msg, msg_len, sk);

	char aux[40];

	strcpy_s(aux, 40, "s_");
	strcat_s(aux, 40, fileName);

	ferr = fopen_s(&fplaintext, aux, "wb");
	fwrite(sig, 1, crypto_sign_BYTES, fplaintext);
	fwrite(msg, 1, msg_len, fplaintext);
	fclose(fplaintext);

	printf("\n-I- Se ha firmado el archivo\n\n");

	return true;
}

bool signCheck(const char* fileName, unsigned char* pk) {
	FILE * fplaintext;
	FILE * ftest;

	errno_t ferr = fopen_s(&fplaintext, fileName, "rb");
	fseek(fplaintext, 0, SEEK_END);
	long signed_msg_len = ftell(fplaintext);
	fseek(fplaintext, 0, SEEK_SET);
	unsigned char *msg = (unsigned char *)malloc(signed_msg_len + 1 - crypto_sign_BYTES);
	unsigned char sig[crypto_sign_BYTES];
	fread(sig, 1, crypto_sign_BYTES, fplaintext);
	fread(msg, 1, signed_msg_len, fplaintext);
	fclose(fplaintext);

	if (crypto_sign_verify_detached(sig, msg, signed_msg_len - crypto_sign_BYTES, pk) != 0) {
		printf("-I- Firma Incorrecta!\n\n");
		return false;
	}
	printf("-I- Firma correcta!\n\n");
	return true;
}

void displayMenu() {
	printf("Bienvenido, selecciona la accion que quieras hacer:\n1. Generacion y recuperacion de claves hacia o desde un archivo"
		"\n2. Cifrado de archivos \n3. Decifrado de archivos \n4. Firma de archivos \n5. Verificacion de firma de archivos \n6. Salir\n");
}

bool keysGeneration(const char* fileName, unsigned char* key, unsigned char* nonce, unsigned char* pk, unsigned char* sk) {
	FILE* fkeys;
	errno_t ferr = fopen_s(&fkeys, fileName, "rb");
	if (fkeys) {
		fread(key, 1, crypto_stream_chacha20_KEYBYTES, fkeys);
		fread(nonce, 1, crypto_stream_chacha20_NONCEBYTES, fkeys);
		fread(pk, 1, crypto_sign_PUBLICKEYBYTES, fkeys);
		fread(sk, 1, crypto_sign_SECRETKEYBYTES, fkeys);

		printf("\n-I-*****Se Cargaron las claves*****\n\n");
	}	
	else {
		ferr = fopen_s(&fkeys, fileName, "wb");
		crypto_secretbox_keygen(key);
		randombytes_buf(nonce, crypto_stream_chacha20_NONCEBYTES);
		crypto_sign_keypair(pk, sk);

		fwrite(key, 1, crypto_stream_chacha20_KEYBYTES, fkeys);
		fwrite(nonce, 1, crypto_stream_chacha20_NONCEBYTES, fkeys);
		fwrite(pk, 1, crypto_sign_PUBLICKEYBYTES, fkeys);
		fwrite(sk, 1, crypto_sign_SECRETKEYBYTES, fkeys);

		printf("\n-I-*****Se generaron y cargaron las claves*****\n\n");
	}
	fclose(fkeys);
	return true;
}

void menu() {
	char option;
	char fileName[30];
	unsigned char key[crypto_stream_chacha20_KEYBYTES];
	unsigned char nonce[crypto_stream_chacha20_NONCEBYTES];
	unsigned char pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sk[crypto_sign_SECRETKEYBYTES];

	do {
		fflush(stdin);
		fflush(stdout);
		displayMenu();
		option = getchar();
		//system("CLS");
		printf("\ningrese el nombre del archivo: ");
		scanf_s("%29s", fileName, (unsigned)_countof(fileName));
		switch (option)
		{
		case '1'://Generacion y recuperacion de claves hacia o desde 1 archivo
			keysGeneration(fileName, key, nonce, pk, sk);
			break;
		case '2': //cifrado
			cipherFile(fileName,  key, nonce);
			break;
		case '3': //decifrado
			decipherFile(fileName, key, nonce);
			break;
		case '4': //firma de archivos
			signFile(fileName, sk);
			break;
		case '5': //verficacion firma
			signCheck(fileName, pk);
			break;
		case '6': //salida del sistema
			printf("\nHasta la proxima!");
			break;
		default:
			break;
		}
		getchar();//para evitar problemas con el buffer de entrada de datos
	} while (option != '6');
}



int main()
{
	if (sodium_init() < 0) {
		return -1;
	}

	

	menu();

	return 0;
}

