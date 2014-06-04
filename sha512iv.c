/* ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  
 * All rights reserved according to the OpenSSL license 
 * See ./LICENCE for further Details
 * ====================================================================
 *
 * Implementation of SHA512 with custom initial vector (IV) h_0 .. h_7
 *
 * Derived from OpenSSL file crypto/sha/sha512.c 
 *
 * Author: Otto Dietz <otto.dietz@physik.hu-berlin.de>
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>

#define SHA512_IV_WORDS 8

// Init SHA512 with custom IV h
int SHA512_Init_iv(SHA512_CTX *c, unsigned long long *h)
 {
		  int i;
		  
		  for (i=0;i<SHA512_IV_WORDS;i++) c->h[i] = *(h+i);

        c->Nl=0; c->Nh=0;
        c->num=0; c->md_len=SHA512_DIGEST_LENGTH;
        return 1;
 }


// Calculate SHA512. Calls SHA512_Init_iv instead of SHA512_Init.
unsigned char *SHA512iv(const unsigned char *d, size_t n, unsigned char *md, unsigned long long *h)
	{
	SHA512_CTX c;
	static unsigned char m[SHA512_DIGEST_LENGTH];

	if (md == NULL) md=m;
	SHA512_Init_iv(&c,h);
	SHA512_Update(&c,d,n);
	SHA512_Final(md,&c);
	OPENSSL_cleanse(&c,sizeof(c));
	return(md);
	}



/*
 * For test and debug purposes only
 */

int put_hex_string(unsigned char *buf){
    int i;
    for (i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        printf("%02x ", buf[i]);
		  if (31 == i) printf("\n");
    }
    printf("\n\n");
}


int main()
{
    unsigned char ibuf[] = "test input string";
	 // sha-512(ibuf) from with independent source
	 unsigned char ibufhash[] = "\x36\xee\x5f\x7d\x28\xa8\xf3"
				"\x56\x92\xd7\x1c\x0c\x1c\x78\xee\xc1\xc9\xe4\xb9\x5f\xa4\x08\x02\x60\x68\xd5\x5a"
				"\x70\x41\x70\x00\x8d\xa2\x19\x8f\x16\xd9\x7c\x90\x13\xea\x56\x42\x45\x4f\x08\xc6"
				"\x2f\xcb\x2e\xf2\xa8\x3c\x21\xbe\x61\x7f\x80\x10\x35\x08\xd8\x10\xaf";

    unsigned char obuf[SHA512_DIGEST_LENGTH];
	 unsigned long long h[SHA512_IV_WORDS];

	 printf("SHA512_DIGEST_LENGTH: %d\n",SHA512_DIGEST_LENGTH);

    // original sha-512 iv from openssl
    h[0]=U64(0x6a09e667f3bcc908);
    h[1]=U64(0xbb67ae8584caa73b);
    h[2]=U64(0x3c6ef372fe94f82b);
    h[3]=U64(0xa54ff53a5f1d36f1);
    h[4]=U64(0x510e527fade682d1);
    h[5]=U64(0x9b05688c2b3e6c1f);
    h[6]=U64(0x1f83d9abfb41bd6b);
    h[7]=U64(0x5be0cd19137e2179);
    

	 printf("New implemenatation sha512iv() with old IV supplied as argument\n");
    SHA512iv(ibuf, strlen(ibuf), obuf, h);
	 put_hex_string(obuf);

	 printf("OpenSSL Implemntation sha512() with build in IV\n");
    SHA512(ibuf, strlen(ibuf), obuf);
	 put_hex_string(obuf);

	 printf("SHA512 of \"test input string\" generated from independent source");
	 put_hex_string(ibufhash);
    
	 return 0;
}

