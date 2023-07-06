#include "MyCrypt.h"

MyCrypt::MyCrypt(PBYTE pbInAES256Key, SIZE_T szInAES256Key)
{
    DWORD dwError = 0;


    if (!pbInAES256Key || szInAES256Key != 32)
    {
        throw MyCryptException("Key must be 32 bytes");
        return;
    }

    if (GenIV() != 0)
    {
        throw MyCryptException("GenIV");
        return;
    }

    // Open an algorithm handle.
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &hAesAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return;
    }

    // Calculate the size of the buffer to hold the KeyObject.
    if (!NT_SUCCESS(status = BCryptGetProperty(
        hAesAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbKeyObject,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return;
    }

    // Allocate the key object on the heap.
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (NULL == pbKeyObject)
    {
        wprintf(L"**** memory allocation failed\n");
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return;
    }

    // Calculate the block length for the IV.
    if (!NT_SUCCESS(status = BCryptGetProperty(
        hAesAlg,
        BCRYPT_BLOCK_LENGTH,
        (PBYTE)&cbBlockLen,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return;
    }

    /*if (!NT_SUCCESS(status = BCryptGenRandom(
        BCRYPT_RNG_ALG_HANDLE,
        (PBYTE)rgbIV,
        sizeof(rgbIV),
        0
    )))
    {
        printf("REE: 0x%x\n", status);
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return;
    }*/

   

    STATUS_INVALID_HANDLE;
    STATUS_INVALID_PARAMETER;

    
    // Determine whether the cbBlockLen is not longer than the IV length.
    if (cbBlockLen > sizeof(rgbIV))
    {
        wprintf(L"**** block length is longer than the provided IV length\n");
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return;
    }

    // Allocate a buffer for the IV. The buffer is consumed during the 
    // encrypt/decrypt process.
    pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlockLen);
    if (NULL == pbIV)
    {
        wprintf(L"**** memory allocation failed\n");
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return;
    }

    memcpy(pbIV, (PBYTE)rgbIV, cbBlockLen);

    if (!NT_SUCCESS(status = BCryptSetProperty(
        hAesAlg,
        BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptSetProperty\n", status);
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return;
    }



    // Generate the key from supplied input key bytes.
    if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(
        hAesAlg,
        &hKey,
        pbKeyObject,
        cbKeyObject,
        (PBYTE)pbInAES256Key,
        szInAES256Key,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return;
    }


    // Save another copy of the key for later.
    if (!NT_SUCCESS(status = BCryptExportKey(
        hKey,
        NULL,
        BCRYPT_OPAQUE_KEY_BLOB,
        NULL,
        0,
        &cbBlob,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return;
    }


    // Allocate the buffer to hold the BLOB.
    pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob);
    if (NULL == pbBlob)
    {
        wprintf(L"**** memory allocation failed\n");
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return;
    }

    if (!NT_SUCCESS(status = BCryptExportKey(
        hKey,
        NULL,
        BCRYPT_OPAQUE_KEY_BLOB,
        pbBlob,
        cbBlob,
        &cbBlob,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return;
    }
}

MyCrypt::~MyCrypt()
{
    if (hAesAlg)
    {
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
    }

    if (hKey)
    {
        BCryptDestroyKey(hKey);
    }

    if (pbCipherText)
    {
        HeapFree(GetProcessHeap(), 0, pbCipherText);
    }

    if (pbPlainText)
    {
        HeapFree(GetProcessHeap(), 0, pbPlainText);
    }

    if (pbKeyObject)
    {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }

    if (pbIV)
    {
        HeapFree(GetProcessHeap(), 0, pbIV);
    }
}

int MyCrypt::GenIV()
{
    DWORD dwError = 0;
    BCRYPT_ALG_HANDLE hAlg = NULL;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_RNG_ALGORITHM,
        NULL,
        0
    )))
    {
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        return dwError;
    }

    if (!NT_SUCCESS(BCryptGenRandom(
        hAlg,
        (PBYTE)rgbIV,
        sizeof(rgbIV),
        0
    )))
    {
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        return dwError;
    }

    BCryptCloseAlgorithmProvider(
        hAlg, 0
    );


    puts("HEREERERE");
    PrintBytes(rgbIV, sizeof(rgbIV));

    return 0;
}

int MyCrypt::Encrypt(PBYTE pbIn, SIZE_T szIn)
{
    /*cbPlainText = sizeof(rgbPlaintext);*/
    DWORD dwError = 0;

    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, szIn);
    if (NULL == pbPlainText)
    {
        wprintf(L"**** memory allocation failed\n");
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return dwError;
    }

    cbPlainText = szIn;

    memcpy(pbPlainText, pbIn, szIn);

    //
    // Get the output buffer size.
    //
    if (!NT_SUCCESS(status = BCryptEncrypt(
        hKey,
        pbPlainText,
        cbPlainText,
        NULL,
        pbIV,
        cbBlockLen,
        NULL,
        0,
        &cbCipherText,
        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return dwError;
    }

    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
    if (NULL == pbCipherText)
    {
        wprintf(L"**** memory allocation failed\n");
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return dwError;
    }

    // Use the key to encrypt the plaintext buffer.
    // For block sized messages, block padding will add an extra block.
    if (!NT_SUCCESS(status = BCryptEncrypt(
        hKey,
        pbPlainText,
        cbPlainText,
        NULL,
        pbIV,
        cbBlockLen,
        pbCipherText,
        cbCipherText,
        &cbData,
        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return dwError;
    }

    // Destroy the key and reimport from saved BLOB.
    if (!NT_SUCCESS(status = BCryptDestroyKey(hKey)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptDestroyKey\n", status);
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return dwError;
    }
    hKey = 0;

    if (pbPlainText)
    {
        HeapFree(GetProcessHeap(), 0, pbPlainText);
    }

    pbPlainText = NULL;

    // We can reuse the key object.
    memset(pbKeyObject, 0, cbKeyObject);

    return 0;
}

int MyCrypt::Decrypt(PBYTE pbOut, SIZE_T szOut)
{
    DWORD dwError = 0;

    // Reinitialize the IV because encryption would have modified it.
    memcpy(pbIV, (PBYTE)rgbIV, cbBlockLen);

    if (!NT_SUCCESS(status = BCryptImportKey(
        hAesAlg,
        NULL,
        BCRYPT_OPAQUE_KEY_BLOB,
        &hKey,
        pbKeyObject,
        cbKeyObject,
        pbBlob,
        cbBlob,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return dwError;
    }

    //
    // Get the output buffer size.
    //
    if (!NT_SUCCESS(status = BCryptDecrypt(
        hKey,
        pbCipherText,
        cbCipherText,
        NULL,
        pbIV,
        cbBlockLen,
        NULL,
        0,
        &cbPlainText,
        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptDecrypt\n", status);
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return dwError;
    }

    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (NULL == pbPlainText)
    {
        wprintf(L"**** memory allocation failed\n");
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return dwError;
    }

    if (!NT_SUCCESS(status = BCryptDecrypt(
        hKey,
        pbCipherText,
        cbCipherText,
        NULL,
        pbIV,
        cbBlockLen,
        pbPlainText,
        cbPlainText,
        &cbPlainText,
        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptDecrypt\n", status);
        dwError = GetLastError();
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return dwError;
    }

    /*if (0 != memcmp(pbPlainText, (PBYTE)rgbPlaintext, sizeof(rgbPlaintext)))
    {
        wprintf(L"Expected decrypted text comparison failed.\n");
        DERR(std::system_category().message(dwError).c_str(), dwError);
        throw MyCryptException("Err");
        return dwError;
    }*/

    memcpy(pbOut, pbPlainText, szOut);

#ifndef NDEBUG
    DMSG("Decrypted: ");
    PrintBytes(pbPlainText, cbPlainText);
    puts("");
#endif
    return 0;
}

void MyCrypt::PrintBytes(
    IN BYTE* pbPrintData,
    IN DWORD    cbDataLen)
{
    DWORD dwCount = 0;

    for (dwCount = 0; dwCount < cbDataLen; dwCount++)
    {
        printf("0x%02x, ", pbPrintData[dwCount]);

        if (0 == (dwCount + 1) % 10) putchar('\n');
    }

}
