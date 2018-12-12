#include <stdio.h>
#include <string.h>
#include <string>
#include <stdlib.h>
#include <time.h>

#include <math.h>

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

void dumpBuf(unsigned char *Buf, unsigned BufLen) {
    unsigned i = 0, j = 0;
    fprintf(stderr, "Len: %u\n", BufLen);
    for (i = 0; i < BufLen; i = i + 16) {
        for (j = 0; (j < 16) && ((i + j) < BufLen); ++j) {
            fprintf(stderr, "%02x ", Buf[i + j]);
        }
        fprintf(stderr, "\n");
    }
}

int main(int argc, char **argv) {
    time_t seconds;
    unsigned i, j, BufLen, KeyLen, AADLen;
    int ret;
    unsigned char *Buf, *BufEncrypted, *BufDecrypted, *Key, *IV, *IV2, *Tag, *AAD;

    seconds = time(NULL);
    printf("Seed = %lu\n", (unsigned long) seconds);

    /* Intializes random number generator */
    srand(seconds);

    KeyLen = 32;

    // Setup a random buffer 500K buffer.
    BufLen = 512 + (1024 * rand() % 100);
    Buf = (unsigned char *) malloc(BufLen);
    if (!Buf)
        return 1;
    for (j = 0; j < BufLen; j++) {
        Buf[j] = rand();
    }

    // Setup a random AAD 500K buffer.
    AADLen = 512 + (1024 * rand() % 10);
    AAD = (unsigned char *) malloc(AADLen);
    if (!Buf)
        return 1;
    for (j = 0; j < AADLen; j++) {
        AAD[j] = rand();
    }

    // Pick a random key and IV
    Key = (unsigned char *) malloc(KeyLen);
    IV  = (unsigned char *) malloc(KeyLen);
    IV2  = (unsigned char *) malloc(KeyLen);
    Tag = (unsigned char *) malloc(KeyLen);
    if (!Buf)
        return 1;
    for (j = 0; j < KeyLen; j++) {
        Key[j] = rand();
        IV[j] = rand();
        IV2[j] = IV[j];
        Tag[j] = rand();
    }

    BufEncrypted = (unsigned char *) malloc(BufLen + AADLen);
    BufDecrypted = (unsigned char *) malloc(BufLen + AADLen);
    if (!BufEncrypted || !BufDecrypted)
        return 1;

    ret = AESEncryptGCM(Buf, BufLen, AAD, AADLen, Key, IV, 7, BufEncrypted, Tag, 14);
    if (ret < 0) {
        fprintf(stderr, "Error, AESEncryptCCM returned: %d\n", ret);
        return 5;
    }

    ret = AESDecryptGCM(BufEncrypted, ret, AAD, AADLen, Tag, 14, Key, IV2, 7, BufDecrypted);
    if (ret < 0) {
        fprintf(stderr, "Error, AESDecryptCCM returned: %d\n", ret);
        return 6;
    }

    if (memcmp(Buf, BufDecrypted, BufLen) != 0) {
            fprintf(stderr, "Error, Round trip encrypt/decrypt failedn");
            fprintf(stderr, "Buf:\n");
            dumpBuf(Buf, BufLen);
            fprintf(stderr, "BufDecrypted:\n");
            dumpBuf(BufDecrypted, BufLen);
            return 7;
    } else {
        printf("round trip successful\n");
    }

    free(Buf);
    free(AAD);
    free(BufEncrypted);
    free(BufDecrypted);
    free(Key);
    free(IV);
    free(IV2);
    free(Tag);
}