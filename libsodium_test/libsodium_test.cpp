// libsodium_test.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#include <iostream>
#include <iomanip>
#include "sodium.h"
#include <fstream>
#include "libsodium_test.h"
#include <stdio.h>
#include <stdlib.h>

int main()
{
	if (sodium_init() < 0) {
		return -1;
	}

    std::cout << "Hello World!\n";
	/*unsigned char buf[32];
	randombytes_buf(buf, sizeof buf);
	for (int i = 0; i < sizeof buf; i++)
		std::cout << std::setfill('0') << std::setw(2) << std::hex << int(buf[i]);
	std::cout << std::endl;*/

	FILE *fplaintext;
	FILE *fciphertext;
	FILE *fdeciphertext;

	//Crear un archivo para leer el mensaje
	/*fplaintext = fopen("plaintext.txt", "w");
	fprintf(fplaintext, "Mensaje que se va a cifrar osiosi\nlinea dos");
	fclose(fplaintext);*/

	//Leer el mensaje del archivo
	errno_t ferr = fopen_s(&fplaintext, "plaintext.txt", "rb"); 
	fseek(fplaintext, 0, SEEK_END);
	long plain_text_len = ftell(fplaintext);
	fseek(fplaintext, 0, SEEK_SET);
	unsigned char *plain_text = (unsigned char *) malloc(plain_text_len + 1);
	fread(plain_text, 1, plain_text_len, fplaintext);
	fclose(fplaintext);

	unsigned char* cipher_text = new unsigned char[plain_text_len];
	unsigned char* decipher_text = new unsigned char[plain_text_len];
	unsigned char key[crypto_stream_chacha20_KEYBYTES];
	unsigned char nonce[crypto_stream_chacha20_NONCEBYTES];

	crypto_secretbox_keygen(key);
	randombytes_buf(nonce, crypto_stream_chacha20_NONCEBYTES);

	//Cifrado y creacion del archivo
	int errorcode = crypto_stream_chacha20_xor(cipher_text, plain_text, plain_text_len, nonce, key);
	for (int i = 0; i < plain_text_len; i++)
		std::cout << std::setfill('0') << std::setw(2) << std::hex << int(cipher_text[i]);
	std::cout << std::endl;

	ferr = fopen_s(&fciphertext,"ciphertext.txt", "w");
	fprintf(fciphertext, "%s", cipher_text);
	fclose(fciphertext);

	//Decifrado y creacion del archivo
	errorcode = crypto_stream_chacha20_xor(decipher_text, cipher_text, plain_text_len, nonce, key);
	for (int i = 0; i < plain_text_len; i++)
		std::cout << std::setfill('0') << std::setw(2) << std::hex << int(decipher_text[i]);
	std::cout << std::endl;
	std::cout << decipher_text;

	ferr = fopen_s(&fdeciphertext,"deciphertext.txt", "w");
	fprintf(fdeciphertext, "%s", decipher_text);
	fclose(fdeciphertext);
	
	return 0;
}

// Ejecutar programa: Ctrl + F5 o menú Depurar > Iniciar sin depurar
// Depurar programa: F5 o menú Depurar > Iniciar depuración

// Sugerencias para primeros pasos: 1. Use la ventana del Explorador de soluciones para agregar y administrar archivos
//   2. Use la ventana de Team Explorer para conectar con el control de código fuente
//   3. Use la ventana de salida para ver la salida de compilación y otros mensajes
//   4. Use la ventana Lista de errores para ver los errores
//   5. Vaya a Proyecto > Agregar nuevo elemento para crear nuevos archivos de código, o a Proyecto > Agregar elemento existente para agregar archivos de código existentes al proyecto
//   6. En el futuro, para volver a abrir este proyecto, vaya a Archivo > Abrir > Proyecto y seleccione el archivo .sln
