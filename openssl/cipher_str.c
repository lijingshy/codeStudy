#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

unsigned char* aes_128_ecb_encrypt_string(const unsigned char* in, int inl, int* outl, const unsigned char *key, bool enc)
{
    const EVP_CIPHER* c=EVP_aes_128_ecb();
    EVP_CIPHER_CTX ctx;
    unsigned char* out = NULL;
    int outl1 = 0, outl2 = 0;

    out = (unsigned char *)OPENSSL_malloc(EVP_ENCODE_LENGTH(inl));

    EVP_CIPHER_CTX_init(&ctx);
    if (enc)
    {
        if(!EVP_EncryptInit_ex(&ctx,c,NULL,key,NULL))
        {
            return NULL;
        }

        if(!EVP_EncryptUpdate(&ctx,out,&outl1,in,inl))
        {
            return NULL;
        }
        if(!EVP_EncryptFinal_ex(&ctx,out+outl1,&outl2))
        {
            return NULL;
        }

        *outl = outl1+outl2;
        return out;
    }
    else
    {
        if(!EVP_DecryptInit_ex(&ctx,c,NULL,key,NULL))
        {
            return NULL;
        }

        if(!EVP_DecryptUpdate(&ctx,out,&outl1,in,inl))
        {
            return NULL;
        }
        if(!EVP_DecryptFinal_ex(&ctx,out+outl1,&outl2))
        {
            return NULL;
        }

        *outl = outl1+outl2;
        return out;
    }

end:
    if (out != NULL) OPENSSL_free(out);
    return NULL;
}

int main(int argc,char **argv)
{
    const char* key = "abc123";
    const char* in = "Do I need patent licenses to use theeee OpenSSL?";

    int outl;
    unsigned char* en_str = aes_128_ecb_encrypt_string((unsigned char*)in, strlen(in), &outl, (unsigned char*)key, true);

    for (int i = 0; i < outl; ++i)
        printf("%02x ", en_str[i]);
    printf("\n");

    unsigned char* de_str = aes_128_ecb_encrypt_string((unsigned char*)en_str, outl, &outl, (unsigned char*)key, false);

    for (int i = 0; i < outl; ++i)
        printf("%c ", de_str[i]);
    printf("\n");

    if (en_str != NULL) OPENSSL_free(en_str);
    if (de_str != NULL) OPENSSL_free(de_str);

    return 0;
}
