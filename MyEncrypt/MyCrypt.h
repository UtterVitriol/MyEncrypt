#pragma once

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <system_error>

#pragma comment(lib, "Bcrypt.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#define DATA_TO_ENCRYPT  "Test Data"

#ifndef NDEBUG
#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#define DERR(s, d) fprintf(stderr, "[-]: %s:%d:%s(): %s - %d\n", __FILENAME__, __LINE__, __func__, s, d)
#define DMSG(s) printf("[+]: %s:%d:%s(): %s\n", __FILENAME__, __LINE__, __func__, s)
#else
#define DERR(s,d)
#define DMSG(s)
#endif

class MyCryptException : public std::exception
{
public:
	MyCryptException(PCSTR message0) : message(message) {}

	PCSTR what()
	{
		return message;
	}

private:
	PCSTR message;
};

class MyCrypt
{
public:
	MyCrypt(PBYTE pbInAES256Key, SIZE_T szInAES256Key);
	~MyCrypt();

	static void PrintBytes(
		IN BYTE* pbPrintData,
		IN DWORD    cbDataLen);

	int Encrypt(PBYTE pbInPlainText, SIZE_T szInPlainText);
	int Decrypt(PBYTE pbOutPlainText, SIZE_T szOutPlainText);

private:

	int GenIV();

	BCRYPT_ALG_HANDLE hAesAlg = NULL;

	BCRYPT_KEY_HANDLE hKey = NULL;

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	DWORD cbCipherText = 0;
	DWORD cbPlainText = 0;
	DWORD cbData = 0;
	DWORD cbKeyObject = 0;
	DWORD cbBlockLen = 0;
	DWORD cbBlob = 0;

	PBYTE pbCipherText = NULL;
	PBYTE pbPlainText = NULL;
	PBYTE pbKeyObject = NULL;
	PBYTE pbBlob = NULL;
	PBYTE pbIV = NULL;

	BYTE rgbIV[16] = {0};
};

