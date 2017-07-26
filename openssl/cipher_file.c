#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>

#define BSIZE   (8*1024)

#define KEY "abc123"
#define IN_NAME "pid.c" 
#define EN_NAME "pid.c.en" 
#define DE_NAME "pid.c.de" 

int ase_128_ecb_encrypt_file(const char* inf, const char* outf, const char* key, bool enc, bool base64)
{
    static const char magic[]="dMan__";
    char mbuf[sizeof magic-1];
	unsigned char *buff=NULL;
	int bsize=BSIZE;
	int inl = 0, ret = 0;
	const EVP_CIPHER *cipher=NULL;
	EVP_CIPHER_CTX *ctx = NULL;
	BIO *in=NULL,*out=NULL,*b64=NULL,*benc=NULL,*rbio=NULL,*wbio=NULL;

    buff=(unsigned char *)OPENSSL_malloc(EVP_ENCODE_LENGTH(bsize));

    //OpenSSL_add_all_ciphers();
    //cipher=EVP_get_cipherbyname("aes-128-ecb");
    cipher=EVP_aes_128_ecb();

	in=BIO_new(BIO_s_file());
	out=BIO_new(BIO_s_file());

    if (BIO_read_filename(in, inf) <= 0)
    {
        ret = -1;
        goto end;
    }

    if (BIO_write_filename(out, (char*)outf) <= 0)
    {
        ret = -1;
        goto end;
    }

	rbio=in;
	wbio=out;

    if (base64)
    {
        if ((b64=BIO_new(BIO_f_base64())) == NULL)
        {
            ret = -1;
            goto end;
        }
        if (enc)
            wbio=BIO_push(b64,wbio);
        else
            rbio=BIO_push(b64,rbio);
    }
    
    //magic
    if(enc) 
    {
        if(BIO_write(wbio,magic,sizeof magic-1) != sizeof magic-1) 
        {
            ret = -1;
            goto end;
        }
    } 
    else if(BIO_read(rbio,mbuf,sizeof mbuf) != sizeof mbuf)
    {
        ret = -1;
        goto end;
    } 
    else if(memcmp(mbuf,magic,sizeof magic-1)) 
    {
        ret = -1;
        goto end;
    }

    //cipher
    if ((benc=BIO_new(BIO_f_cipher())) == NULL) 
    {
        ret = -1;
        goto end;
    }

    BIO_get_cipher_ctx(benc, &ctx);
    if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc))
    {
        ret = -1;
        goto end;
    }

    if (!EVP_CipherInit_ex(ctx, NULL, NULL, (unsigned char*)key, NULL, enc))
    {
        ret = -1;
        goto end;
    }

	if (benc != NULL)
		wbio=BIO_push(benc,wbio);

    for (;;)
    {
        inl=BIO_read(rbio,(char *)buff,bsize);
        if (inl <= 0) break;
        if (BIO_write(wbio,(char *)buff,inl) != inl)
        {
            ret = -1;
            goto end;
        }
    }
    if (!BIO_flush(wbio))
    {
        ret = -1;
        goto end;
    }

    //clear
end:
	if (buff != NULL) OPENSSL_free(buff);
	if (in != NULL) BIO_free(in);
	if (out != NULL) BIO_free_all(out);
	if (benc != NULL) BIO_free(benc);
	if (b64 != NULL) BIO_free(b64);
    
    return ret;
}

int main(int argc, char* argv[])
{
    ase_128_ecb_encrypt_file(IN_NAME, EN_NAME, KEY, true, false);

    ase_128_ecb_encrypt_file(EN_NAME, DE_NAME, KEY, false, false);

    return 0;
}
