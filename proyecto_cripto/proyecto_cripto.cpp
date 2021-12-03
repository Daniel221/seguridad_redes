// proyecto_cripto.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <iomanip>
#include "sodium.h"

bool cipherfile(const char* textFileName, const char* cipherFileName, unsigned char* key, unsigned char* nonce) {
	FILE * fplaintext;
	FILE * fciphertext;
	try {
		errno_t ferr = fopen_s(&fplaintext, textFileName, "rb");
		fseek(fplaintext, 0, SEEK_END);
		long plain_text_len = ftell(fplaintext);
		fseek(fplaintext, 0, SEEK_SET);
		unsigned char *plain_text = (unsigned char *)malloc(plain_text_len + 1);
		fread(plain_text, 1, plain_text_len, fplaintext);
		fclose(fplaintext);

		unsigned char* cipher_text = new unsigned char[plain_text_len];
		int errorcode = crypto_stream_chacha20_xor(cipher_text, plain_text, plain_text_len, nonce, key);

		ferr = fopen_s(&fciphertext, cipherFileName, "w");
		fprintf(fciphertext, "%s", cipher_text);
		fclose(fciphertext);
	}
	catch (std::exception& e) {
		printf(e.what());
	}

	

	return true;
}

bool decipherfile(const char* textFileName, const char* cipherFileName, unsigned char* key, unsigned char* nonce) {
	FILE* fciphertext;
	FILE* fdeciphertext;
	

	errno_t ferr = fopen_s(&fciphertext, textFileName, "rb");
	fseek(fciphertext, 0, SEEK_END);
	long cipher_text_len = ftell(fciphertext);
	fseek(fciphertext, 0, SEEK_SET);
	unsigned char *plain_text = (unsigned char *)malloc(cipher_text_len + 1);
	fread(plain_text, 1, cipher_text_len, fciphertext);
	fclose(fciphertext);

	unsigned char* cipher_text = new unsigned char[cipher_text_len];
	int errorcode = crypto_stream_chacha20_xor(cipher_text, plain_text, cipher_text_len, nonce, key);

	ferr = fopen_s(&fdeciphertext, cipherFileName, "w");
	fprintf(fdeciphertext, "%s", cipher_text);
	fclose(fdeciphertext);

	return true;
}

void displayMenu() {
	printf("Bienvenido, selecciona la accion que quieras hacer:\n1. Generacion y recuperacion de claves hacia o desde un archivo"
		"\n2. Cifrado de archivos \n3. Decifrado de archivos \n4. Firma de archivos \n5. Verificacion de firma de archivos \n6. Salir\n");
}

void menu() {
	char option;
	unsigned char key[crypto_stream_chacha20_KEYBYTES];
	unsigned char nonce[crypto_stream_chacha20_NONCEBYTES];

	crypto_secretbox_keygen(key);
	randombytes_buf(nonce, crypto_stream_chacha20_NONCEBYTES);
	
	do {
		system("CLS");
		displayMenu();
		option = getchar();
		switch (option)
		{
		case '1'://Generacion y recuperacion de claves hacia o desde 1 archivo
			break;
		case '2': //cifrado
			cipherfile("plaintext.txt", "ciphertext.txt", key, nonce);
			break;
		case '3': //decifrado
			decipherfile("ciphertext.txt", "deciphertext.txt", key, nonce);
			break;
		case '4': //firma de archivos
			break;
		case '5': //verficacion firma
			break;
		case '6': //salida del sistema
			printf("\nHasta la proxima!");
			break;
		default:
			break;
		}
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

