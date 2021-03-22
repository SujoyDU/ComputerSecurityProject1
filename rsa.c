#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rsa.h"
#include "prf.h"
#include <stdbool.h>

/* NOTE: a random composite surviving 10 Miller-Rabin tests is extremely
 * unlikely.  See Pomerance et al.:
 * http://www.ams.org/mcom/1993-61-203/S0025-5718-1993-1189518-9/
 * */
#define ISPRIME(x) mpz_probab_prime_p(x,10)
#define NEWZ(x) mpz_t x; mpz_init(x)
#define BYTES2Z(x,buf,len) mpz_import(x,len,-1,1,0,0,buf)
#define Z2BYTES(buf,len,x) mpz_export(buf,&len,-1,1,0,0,x)

/* utility function for read/write mpz_t with streams: */
int zToFile(FILE* f, mpz_t x)
{
	size_t i,len = mpz_size(x)*sizeof(mp_limb_t);
	/* NOTE: len may overestimate the number of bytes actually required. */
	unsigned char* buf = malloc(len);
	Z2BYTES(buf,len,x);
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b = (len >> 8*i) % 256;
		fwrite(&b,1,1,f);
	}
	fwrite(buf,1,len,f);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}
int zFromFile(FILE* f, mpz_t x)
{
	size_t i,len=0;
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b;
		/* XXX error check this; return meaningful value. */
		fread(&b,1,1,f);
		len += (b << 8*i);
	}
	unsigned char* buf = malloc(len);
	fread(buf,1,len,f);
	BYTES2Z(x,buf,len);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}

int rsa_keyGen(size_t keyBits, RSA_KEY* K)
{
	rsa_initKey(K);
	/* TODO: write this.  Use the prf to get random byte strings of
	 * the right length, and then test for primality (see the ISPRIME
	 * macro above).  Once you've found the primes, set up the other
	 * pieces of the key ({en,de}crypting exponents, and n=pq). */
    
    //We need to generate 2 random prime numbers for p and q as well as find values for n, e, and d.
    
    //generating random numbers of 16 bytes and converting to integer
    keyBits = 16;
    unsigned char* buf;
    NEWZ(rn);
    NEWZ(rn2);
    buf = malloc(keyBits);
    randBytes(buf, keyBits);
    BYTES2Z(rn, buf, keyBits);
 
    for(size_t i = 0; i<65536; i++)
        {
            mpz_nextprime(rn, rn);
            mpz_set((*K).p, rn);
        }
//frees buf to generate another random number. makes the generated prime numbers more distinct from eachother.
    free(buf);
    buf = malloc(keyBits);
    randBytes(buf, keyBits);
    BYTES2Z(rn2, buf, keyBits);
        
    for(size_t t = 0; t<65536; t++)
        {
            mpz_nextprime(rn2, rn2);
            mpz_set((*K).q, rn2);
        }
        
    free(buf);
    
    //getting a value for n as n=pq
    NEWZ(nv);
    mpz_mul(nv, (*K).q, (*K).p);
    mpz_set((*K).n, nv);
    
    //computing phin as (p-1)(q-1)
    NEWZ(ps1);
    mpz_sub_ui(ps1, (*K).p, 1);
    NEWZ(qs1);
    mpz_sub_ui(qs1, (*K).q, 1);
    NEWZ(phin);
    mpz_mul(phin, ps1, qs1);
    
    //getting a value for e
    NEWZ(e);
    mpz_set_ui(e, 2);
    
    //e and phin both have to be prime that satisfy e>1
    NEWZ(count);
    while(mpz_get_ui(count) < mpz_get_ui(phin))
    {
        mpz_gcd(count, e, phin);
        if(mpz_get_ui(count) == 1)
            break;
        else
            mpz_add_ui(e, e, 1);
    }
    mpz_set((*K).e, e);
    
    //computing d
    mpz_invert((*K).d, (*K).e, phin);
    return 0;
}

size_t rsa_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	/* TODO: write this.  Use BYTES2Z to get integers, and then
	 * Z2BYTES to write the output buffer. */
        NEWZ(etext);
	NEWZ(x);
	BYTES2Z(x, inBuf, len);
	mpz_powm(etext, x, (*K).e, (*K).n);
	Z2BYTES(outBuf, len, etext);
	return len; /* TODO: return should be # bytes written */
}
size_t rsa_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	/* TODO: write this.  See remarks above. */
        NEWZ(dtext);
	NEWZ(x);
	BYTES2Z(x, inBuf, len);
	mpz_powm(dtext, x, (*K).d, (*K).n);
	Z2BYTES(outBuf, len, dtext);
	return len;
}

size_t rsa_numBytesN(RSA_KEY* K)
{
	return mpz_size(K->n) * sizeof(mp_limb_t);
}

int rsa_initKey(RSA_KEY* K)
{
	mpz_init(K->d); mpz_set_ui(K->d,0);
	mpz_init(K->e); mpz_set_ui(K->e,0);
	mpz_init(K->p); mpz_set_ui(K->p,0);
	mpz_init(K->q); mpz_set_ui(K->q,0);
	mpz_init(K->n); mpz_set_ui(K->n,0);
	return 0;
}

int rsa_writePublic(FILE* f, RSA_KEY* K)
{
	/* only write n,e */
	zToFile(f,K->n);
	zToFile(f,K->e);
	return 0;
}
int rsa_writePrivate(FILE* f, RSA_KEY* K)
{
	zToFile(f,K->n);
	zToFile(f,K->e);
	zToFile(f,K->p);
	zToFile(f,K->q);
	zToFile(f,K->d);
	return 0;
}
int rsa_readPublic(FILE* f, RSA_KEY* K)
{
	rsa_initKey(K); /* will set all unused members to 0 */
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	return 0;
}
int rsa_readPrivate(FILE* f, RSA_KEY* K)
{
	rsa_initKey(K);
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	zFromFile(f,K->p);
	zFromFile(f,K->q);
	zFromFile(f,K->d);
	return 0;
}
int rsa_shredKey(RSA_KEY* K)
{
	/* clear memory for key. */
	mpz_t* L[5] = {&K->d,&K->e,&K->n,&K->p,&K->q};
	size_t i;
	for (i = 0; i < 5; i++) {
		size_t nLimbs = mpz_size(*L[i]);
		if (nLimbs) {
			memset(mpz_limbs_write(*L[i],nLimbs),0,nLimbs*sizeof(mp_limb_t));
			mpz_clear(*L[i]);
		}
	}
	/* NOTE: a quick look at the gmp source reveals that the return of
	 * mpz_limbs_write is only different than the existing limbs when
	 * the number requested is larger than the allocation (which is
	 * of course larger than mpz_size(X)) */
	return 0;
}

//Code Todos done by Arun Misir
