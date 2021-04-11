/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */
//  gcc kem-enc.cpp rsa.cpp ske.cpp prf.cpp -o kem-enc -O2 -Wall -std=c++14 -lstdc++ -lgmp -lgmpxx -lcrypto -lssl -I/usr/local/Cellar/openssl@1.1/1.1.1k/include -L/usr/local/Cellar/openssl@1.1/1.1.1k/lib

#include <iostream>
#include <array>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <sys/mman.h>

#include "ske.h"
#include "rsa.h"
#include "prf.h"

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Encrypt or decrypt data.\n\n"
"   -i,--in     FILE   read input from FILE.\n"
"   -o,--out    FILE   write output to FILE.\n"
"   -k,--key    FILE   the key.\n"
"   -r,--rand   FILE   use FILE to seed RNG (defaults to /dev/urandom).\n"
"   -e,--enc           encrypt (this is the default action).\n"
"   -d,--dec           decrypt.\n"
"   -g,--gen    FILE   generate new key and write to FILE{,.pub}\n"
"   -b,--BITS   NBITS  length of new key (NOTE: this corresponds to the\n"
"                      RSA key; the symmetric key will always be 256 bits).\n"
"                      Defaults to %lu.\n"
"   --help             show this message and exit.\n";

#define FNLEN 255
#define HM_LEN 32
enum modes {
	ENC,
	DEC,
	GEN
};

/* Let SK denote the symmetric key.  Then to format ciphertext, we
 * simply concatenate:
 * +------------+----------------+
 * | RSA-KEM(X) | SKE ciphertext |
 * +------------+----------------+
 * NOTE: reading such a file is only useful if you have the key,
 * and from the key you can infer the length of the RSA ciphertext.
 * We'll construct our KEM as KEM(X) := RSA(X)|H(X), and define the
 * key to be SK = KDF(X).  Naturally H and KDF need to be "orthogonal",
 * so we will use different hash functions:  H := SHA256, while
 * KDF := HMAC-SHA512, where the key to the hmac is defined in ske.c
 * (see KDF_KEY).
 * */

#define HASHLEN 32 /* for sha256 */

int kem_encrypt(const char* fnOut, const char* fnIn, RSA_KEY* K){
	
	/* TODO: encapsulate random symmetric key (SK) using RSA and SHA256;
	 * encrypt fnIn with SK; concatenate encapsulation and cihpertext;
	 * write to fnOut. */
	// Open files.
	auto fdin = open(fnIn, O_RDONLY);
	auto fdout = open(fnOut, O_CREAT | O_RDWR, S_IRWXU);
	if(fdin < 0 or fdout < 0) {
        std::cerr << "Failed to open file" << std::endl;
		return -1;
    }
	// Find ciphertext and plaintext length.
	const auto fin_size = lseek(fdin, 0, SEEK_END);
	const auto fout_size = ske_getOutputLen(fin_size) + rsa_numBytesN(K) + HASHLEN;
	ftruncate(fdout, fout_size); // allocates memory in file.

	// Map files to memory.
	auto mmap_in = reinterpret_cast<unsigned char*>(mmap(nullptr, fin_size,
											   		  PROT_READ, MAP_FILE | MAP_SHARED, 
											    	  fdin, 0));

	auto mmap_out = reinterpret_cast<unsigned char*>(mmap(nullptr, fout_size,
											   		  PROT_WRITE, MAP_FILE | MAP_SHARED, 
											    	  fdout, 0));
	
	if(mmap_in == MAP_FAILED or mmap_out == MAP_FAILED){
		std::cerr << "mmap failed" << std::endl;
		return -1;
	}

	// Generate symmetric key
	SKE_KEY SK;
	ske_keyGen(&SK, nullptr, 0);

	// RSA(X)
	rsa_encrypt(mmap_out, reinterpret_cast<unsigned char*>(&SK), sizeof(SK), K);
	
	// H(X)
	SHA256(reinterpret_cast<unsigned char*>(&SK), sizeof(SK), mmap_out + rsa_numBytesN(K));

	// SKE ciphertext
	ske_encrypt(mmap_out + rsa_numBytesN(K) + HASHLEN, mmap_in, fin_size, &SK, nullptr);
	
	// Cleanup.
	munmap(mmap_in, fin_size);
	munmap(mmap_out, fout_size);
	close(fdin);
	close(fdout);

	return 0;
}

/* NOTE: make sure you check the decapsulation is valid before continuing */
int kem_decrypt(const char* fnOut, const char* fnIn, RSA_KEY* K){
	/* TODO: write this. */
	/* step 1: recover the symmetric key */
	/* step 2: check decapsulation */
	/* step 3: derive key from ephemKey and decrypt data. */
	// Open files.
	auto fdin = open(fnIn, O_RDONLY);
	auto fdout = open(fnOut, O_CREAT | O_RDWR, S_IRWXU);
	if(fdin < 0 or fdout < 0) {
        std::cerr << "Failed to open file" << std::endl;
		close(fdin);
		close(fdout);
		return -1;
    }

	// Find ciphertext length.
	const auto fin_size = lseek(fdin, 0, SEEK_END);
	// Map ciphertext to memory.
	auto mmap_in = reinterpret_cast<unsigned char*>(mmap(nullptr, fin_size,
											   		  PROT_READ, MAP_FILE | MAP_SHARED, 
											    	  fdin, 0));
	if(mmap_in == MAP_FAILED){
		std::cerr << "mmap_in failed" << std::endl;
		return -1;
	}

	// Retreive symmetric key.
	SKE_KEY SK = {};
	rsa_decrypt(reinterpret_cast<unsigned char*>(&SK), mmap_in, rsa_numBytesN(K), K);
	
	// Check hash
	std::array<unsigned char, HASHLEN> hash = {};
	SHA256(reinterpret_cast<unsigned char*>(&SK), sizeof(SK), hash.data());

	// Verify decapsulation
	if(not std::equal(hash.begin(), hash.end(), mmap_in + rsa_numBytesN(K))){
		std::cerr<<"kem_decrypt decapsulation check failed"<<std::endl;
		return -1;
	}
	const auto fout_size = fin_size - HASHLEN - rsa_numBytesN(K) - AES_BLOCK_SIZE - HM_LEN;
	auto mmap_out = reinterpret_cast<unsigned char*>(mmap(nullptr, fout_size,
													PROT_WRITE, MAP_FILE | MAP_SHARED, 
													fdout, 0));
	if(mmap_out == MAP_FAILED){
		std::cerr << "mmap_out failed" << std::endl;
		return -1;
	}
	ftruncate(fdout, fout_size);
	
	ske_decrypt(mmap_out, mmap_in + rsa_numBytesN(K) + HASHLEN, fin_size - rsa_numBytesN(K) - HASHLEN, &SK);
	// Cleanup.
	munmap(mmap_in, fin_size);
	munmap(mmap_out, fout_size);
	close(fdin);
	close(fdout);
	return 0;
}

int main(int argc, char *argv[]) {
	/* define long options */
	static struct option long_opts[] = {
		{"in",      required_argument, 0, 'i'},
		{"out",     required_argument, 0, 'o'},
		{"key",     required_argument, 0, 'k'},
		{"rand",    required_argument, 0, 'r'},
		{"gen",     required_argument, 0, 'g'},
		{"bits",    required_argument, 0, 'b'},
		{"enc",     no_argument,       0, 'e'},
		{"dec",     no_argument,       0, 'd'},
		{"help",    no_argument,       0, 'h'},
		{0,0,0,0}
	};
	/* process options: */
	char c;
	int opt_index = 0;
	char fnRnd[FNLEN+1] = "/dev/urandom";
	fnRnd[FNLEN] = 0;
	char fnIn[FNLEN+1];
	char fnOut[FNLEN+1];
	char fnKey[FNLEN+1];
	memset(fnIn,0,FNLEN+1);
	memset(fnOut,0,FNLEN+1);
	memset(fnKey,0,FNLEN+1);
	int mode = ENC;
	// size_t nBits = 2048;
	size_t nBits = 1024;
	while ((c = getopt_long(argc, argv, "edhi:o:k:r:g:b:", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'h':
				printf(usage,argv[0],nBits);
				return 0;
			case 'i':
				strncpy(fnIn,optarg,FNLEN);
				break;
			case 'o':
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'k':
				strncpy(fnKey,optarg,FNLEN);
				break;
			case 'r':
				strncpy(fnRnd,optarg,FNLEN);
				break;
			case 'e':
				mode = ENC;
				break;
			case 'd':
				mode = DEC;
				break;
			case 'g':
				mode = GEN;
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'b':
				nBits = atol(optarg);
				break;
			case '?':
				printf(usage,argv[0],nBits);
				return 1;
		}
	}

	/* TODO: finish this off.  Be sure to erase sensitive data
	 * like private keys when you're done with them (see the
	 * rsa_shredKey function). */
	switch (mode) {
		case ENC:{
			
			// Open file containing key.
			auto pfile_key = fopen(fnKey, "r");
			if(pfile_key == nullptr){
				std::cerr<<"Failed to open fnKey."<<std::endl;
				return 1;
			}
			
			// Retreive rsa key.
			RSA_KEY K;
			rsa_readPublic(pfile_key, &K);

			const auto ret = kem_encrypt(fnOut, fnIn, &K);
			if(ret){
				std::cerr<<"kem_encrypt failed."<<std::endl;
				return 1;
			}

			// Cleanup
			fclose(pfile_key);
			
			// did you say key? what key?
			rsa_shredKey(&K);
			break;
		}
		case DEC:{

			// Open file containing key.
			auto pfile_key = fopen(fnKey, "r");
			if(pfile_key == nullptr){
				std::cerr<<"Failed to open fnKey."<<std::endl;
				return 1;
			}

			// Retreive rsa key.
			RSA_KEY K;
			rsa_readPrivate(pfile_key, &K);

			const auto ret = kem_decrypt(fnOut, fnIn, &K);
			if(ret){
				std::cerr<<"kem_decrypt failed."<<std::endl;
				return 1;
			}

			// Cleanup
			fclose(pfile_key);

			// did you say key? what key?
			rsa_shredKey(&K);
			break;
		}
		case GEN:{

			// Create key files.
			auto pfile_private = fopen(fnOut, "w");

			for(auto i=0; i<FNLEN; ++i){

				if(fnOut[i] == '\0'){
					strcpy(fnOut + i, ".pub");
					i = FNLEN;
				}
			}
			auto pfile_public = fopen(fnOut, "w");
			if(pfile_public == nullptr or pfile_private == nullptr){
				std::cerr<<"Failed to open files to write."<<std::endl;
				fclose(pfile_public);
				fclose(pfile_private);
			}

			// Generate rsa key.
			RSA_KEY K;
			rsa_keyGen(nBits, &K);

			// Save key to files.
			rsa_writePublic(pfile_public, &K);
			rsa_writePrivate(pfile_private, &K);

			// Cleanup
			fclose(pfile_public);
			fclose(pfile_private);

			// did you say key? what key?
			rsa_shredKey(&K);
			break;
		}
		default:
		 	return 1;
	}

	return 0;
}
