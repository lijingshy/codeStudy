#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

unsigned char* aes_128_ecb_encrypt_string(const unsigned char* in, int inl, int* outl, const unsigned char *key, bool enc, bool base64)
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

        if (base64)
        {
            int out1l = outl1+outl2;
            unsigned char* out1 = (unsigned char *)OPENSSL_malloc(out1l);
            memcpy(out1, out, out1l);
            memset(out, 0, EVP_ENCODE_LENGTH(inl));
            EVP_ENCODE_CTX bctx;
            EVP_EncodeInit(&bctx);
            EVP_EncodeUpdate(&bctx, out, &outl1, (unsigned char*)out1, out1l);
            EVP_EncodeFinal(&bctx, out+outl1, &outl2);

            OPENSSL_free(out1);
            *outl = outl1+outl2;
            return out;
        }
        else
        {
            *outl = outl1+outl2;
            return out;
        }
    }
    else
    {
        const unsigned char* din = in;
        int dinl = inl;
        if (base64)
        {
            int dbufl1, dbufl2;
            unsigned char* dbuf = (unsigned char*)OPENSSL_malloc(inl);
            EVP_ENCODE_CTX dctx;
            EVP_DecodeInit(&dctx);
            EVP_DecodeUpdate(&dctx, dbuf, &dbufl1, (unsigned char*)in, inl);
            EVP_DecodeFinal(&dctx, dbuf+dbufl1, &dbufl2);

            din = dbuf;
            dinl = dbufl1 + dbufl2;
        }
        
        if(!EVP_DecryptInit_ex(&ctx,c,NULL,key,NULL))
        {
            if (base64) OPENSSL_free((unsigned char*)din);
            return NULL;
        }

        if(!EVP_DecryptUpdate(&ctx,out,&outl1,din,dinl))
        {
            if (base64) OPENSSL_free((unsigned char*)din);
            return NULL;
        }
        if(!EVP_DecryptFinal_ex(&ctx,out+outl1,&outl2))
        {
            if (base64) OPENSSL_free((unsigned char*)din);
            return NULL;
        }

        if (base64) OPENSSL_free((unsigned char*)din);
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

    bool base64 = true;
    int outl;
    unsigned char* en_str = aes_128_ecb_encrypt_string((unsigned char*)in, strlen(in), &outl, (unsigned char*)key, true, base64);

    if (base64)
        fwrite(en_str,1,outl,stdout);
    else
    {
        for (int i = 0; i < outl; ++i)
            printf("%02x ", en_str[i]);
        printf("\n");
    }


    unsigned char* de_str = aes_128_ecb_encrypt_string((unsigned char*)en_str, outl, &outl, (unsigned char*)key, false, base64);

    fwrite(de_str,1,outl,stdout);
    printf("\n");

    if (en_str != NULL) OPENSSL_free(en_str);
    if (de_str != NULL) OPENSSL_free(de_str);

    return 0;
}
