#include <stdio.h>
#include <string.h>
#include <string>
#include <stdlib.h>
#include <time.h>

using namespace std;

#include <openssl/aes.h>
#include <openssl/evp.h>

int AESEncryptGCM(unsigned char *In, int InLen,
        unsigned char *AAD, int AADLen, unsigned char *Key,
        unsigned char *IV, unsigned IVLen, unsigned char *Out,
        unsigned char *Tag, unsigned TagLen) {
    EVP_CIPHER_CTX *CTX;
    int Len, OutLen;

    // New contxt.
    if (!(CTX = EVP_CIPHER_CTX_new()))
        return -1;

    // Encrypt CCM.
    if (EVP_EncryptInit_ex(CTX, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        return -2;

    // Setting IV len, if not set, default is 12.
    if (IVLen)
        if (EVP_CIPHER_CTX_ctrl(CTX, EVP_CTRL_GCM_SET_IVLEN, IVLen, NULL) != 1)
            return -3;

    // Initialise Key and IV.
    if (EVP_EncryptInit_ex(CTX, NULL, NULL, Key, IV) != 1)
        return -4;

    // Provide any AAD data, if any.
    if (AADLen)
        if (EVP_EncryptUpdate(CTX, NULL, &Len, AAD, AADLen) != 1)
            return -5;

    // Setup what to encrypt.
    if (EVP_EncryptUpdate(CTX, Out, &Len, In, InLen) != 1)
        return -6;
    OutLen = Len;

    // Execute the encryption.
    if (EVP_EncryptFinal_ex(CTX, Out + Len, &Len) != 1)
        return -7;
    OutLen += Len;

    // Get the Tag.
    if (EVP_CIPHER_CTX_ctrl(CTX, EVP_CTRL_GCM_GET_TAG, TagLen, Tag) != 1)
        return -8;

    // Clean up your mess.
    EVP_CIPHER_CTX_free(CTX);

    return OutLen;
}

int AESDecryptGCM(unsigned char *In, int InLen,
        unsigned char *AAD, int AADLen, unsigned char *Tag,
        unsigned TagLen, unsigned char *Key, unsigned char *IV,
        unsigned IVLen, unsigned char *Out) {
    EVP_CIPHER_CTX *CTX;
    int Len, OutLen, ret;

    // New context.
    if(!(CTX = EVP_CIPHER_CTX_new()))
        return -1;

    // Decrypt CCM.
    if(EVP_DecryptInit_ex(CTX, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        return -2;

    // Setting IV Len if we have something, else default is 12.
    if (IVLen)
        if(EVP_CIPHER_CTX_ctrl(CTX, EVP_CTRL_GCM_SET_IVLEN, IVLen, NULL) != 1)
            return -3;

    // Set the Key and IV.
    if (EVP_DecryptInit_ex(CTX, NULL, NULL, Key, IV) != 1)
        return -5;

    // Provide optional AAD data.
    if (AADLen)
        if (EVP_DecryptUpdate(CTX, NULL, &Len, AAD, AADLen) != 1)
            return -7;

    // Decrypt.
    if (!EVP_DecryptUpdate(CTX, Out, &Len, In, InLen))
        return -9;
    OutLen = Len;

    // Set expected Tag value.
    if (EVP_CIPHER_CTX_ctrl(CTX, EVP_CTRL_GCM_SET_TAG, TagLen, Tag) != 1)
        return -4;

    ret = EVP_DecryptFinal_ex(CTX, Out + Len, &Len);
    OutLen += Len;

    // Clean up your mess.
    EVP_CIPHER_CTX_free(CTX);

    if(ret > 0)
        return OutLen; // Decrypted, and verification passed
    else
        return -8; // Verification failed
}

extern "C" {
    int JSAESEncryptGCM(unsigned char *In, int InLen,
        unsigned char *AAD, int AADLen, unsigned char *Key,
        unsigned char *IV, unsigned IVLen, unsigned char *Out,
        unsigned char *Tag, unsigned TagLen) {
            return AESEncryptGCM(In, InLen, AAD, AADLen, Key, IV, IVLen, Out, Tag, TagLen);
        }
}

extern "C" {
    int JSAESDecryptGCM(unsigned char *In, int InLen,
        unsigned char *AAD, int AADLen, unsigned char *Tag,
        unsigned TagLen, unsigned char *Key, unsigned char *IV,
        unsigned IVLen, unsigned char *Out) {
            // printf("InLen=%d\n", InLen);
            // printf("In addr=%p\n", In);
            // for(int i = 0; i < InLen; i++) {
            //     printf("index=%d value=%c\n", i, In[i]);
            // }
            return AESDecryptGCM(In, InLen, AAD, AADLen, Tag, TagLen, Key, IV, IVLen, Out);
        }
}

int main(int argc, char **argv) {
    // not used.
}