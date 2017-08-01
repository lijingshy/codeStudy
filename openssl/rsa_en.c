#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>
#include<openssl/rand.h>
 
#define PRIKEY "prikey.pem"
#define PUBKEY "pubkey.pem"
 
/************************************************************************
 * RSA加密解密函数
 *
 * file: test_rsa_encdec.c
 * gcc -Wall -O2 -o test_rsa_encdec test_rsa_encdec.c -lcrypto -lssl
 *
 * author: tonglulin@gmail.com by www.qmailer.net
 ************************************************************************/
 
unsigned char *my_encrypt(unsigned char *in, char *pubkey_path, bool base64)
{
    RSA *rsa = NULL;
    FILE *fp = NULL;
    unsigned char *en = NULL;
    unsigned char *bbuf = NULL;
    int rsa_len = 0;
    int outl1, outl2;
 
    if ((fp = fopen(pubkey_path, "r")) == NULL) {
        goto err;
    }
 
    /* 读取公钥PEM，PUBKEY格式PEM使用PEM_read_RSA_PUBKEY函数 */
    if ((rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL)) == NULL) {
        goto err;
    }
 
    //RSA_print_fp(stdout, rsa, 0);
 
    rsa_len = RSA_size(rsa);
    en = (unsigned char *)malloc(rsa_len);
    memset(en, 0, rsa_len);
 
    if (RSA_public_encrypt(rsa_len, in, en, rsa, RSA_NO_PADDING) < 0) {
        goto err;
    }

    if (base64)
    {
        int out1l = rsa_len/3*4+1;
        bbuf = (unsigned char *)OPENSSL_malloc(out1l);
        memset(bbuf, '\0', out1l);
        EVP_ENCODE_CTX ectx;
        EVP_EncodeInit(&ectx);
        EVP_EncodeUpdate(&ectx, bbuf, &outl1, en, rsa_len);
        EVP_EncodeFinal(&ectx, bbuf+outl1, &outl2);

        OPENSSL_free(en);
        return bbuf;
    }
 
    RSA_free(rsa);
    fclose(fp);
    return en;

err:
    if (rsa) RSA_free(rsa);
    if (fp) fclose(fp);
    if (bbuf) OPENSSL_free(bbuf);
    if (en) free(en);
    return NULL;
}
 
unsigned char *my_decrypt(unsigned char *in, char *prikey_path, bool base64)
{
    RSA *rsa = NULL;
    FILE *fp = NULL;
    unsigned char *de = NULL;
    unsigned char* bbuf = NULL;
    unsigned char* din = in;
    int rsa_len = 0;
    int outl1, outl2;
 
    if ((fp = fopen(prikey_path, "r")) == NULL) {
        goto err;
    }
 
    if ((rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)) == NULL) {
        goto err;
    }
 
    //RSA_print_fp(stdout, rsa, 0);
 
    rsa_len = RSA_size(rsa);
    de = (unsigned char *)malloc(rsa_len);
    memset(de, 0, rsa_len);

    if (base64)
    {
        bbuf = (unsigned char*)OPENSSL_malloc(rsa_len);
        EVP_ENCODE_CTX dctx;
        EVP_DecodeInit(&dctx);
        EVP_DecodeUpdate(&dctx, bbuf, &outl1, in, strlen((char*)in));
        EVP_DecodeFinal(&dctx, bbuf+outl1, &outl2);

        din = bbuf;
    }
 
    if (RSA_private_decrypt(rsa_len, din, de, rsa, RSA_NO_PADDING) < 0) {
        goto err;
    }
 
    RSA_free(rsa);
    fclose(fp);
    return de;

err:
    if (rsa) RSA_free(rsa);
    if (fp) fclose(fp);
    if (bbuf) OPENSSL_free(bbuf);
    if (de) free(de);
    return NULL;
}
 
//#define STRING

int main(int argc, char *argv[])
{
    bool base64 = true;
#ifdef STRING
    char *src = "hello, world!";
#else
    unsigned char src[32];
    RAND_bytes(src, 32);
#endif

    unsigned char *en = NULL;
    unsigned char *de = NULL;
 
#ifdef STRING
    printf("src is: %s\n", src);
#else
    for (int i = 0; i < 32; ++i)
        printf("%02x ", src[i]);
    printf("\n");
#endif
 
    en = my_encrypt((unsigned char*)src, PUBKEY, base64);

    if (base64)
        printf("%s", en);
    else
        for (int i = 0; i < 128; ++i)
            printf("%02x ", en[i]);
    printf("\n");
 
    de= my_decrypt((unsigned char*)en, PRIKEY, base64);
#ifdef STRING
    printf("dec is: %s\n", de);
#else
    for (int i = 0; i < 32; ++i)
        printf("%02x ", de[i]);
    printf("\n");
#endif
 
    if (en != NULL) {
        free(en);
    }
 
    if (de != NULL) {
        free(de);
    }
 
    return 0;
}

