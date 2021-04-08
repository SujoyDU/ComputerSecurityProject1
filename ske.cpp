#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <memory>

#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+----------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(IV|C) (32 bytes for SHA256) |
 * +------------+--------------------+----------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */
	if(entropy != nullptr){

		std::array<unsigned char, HM_LEN*2> md = {}; // No malloc please

		HMAC(EVP_sha512(), KDF_KEY, HM_LEN, entropy, entLen, md.data(), nullptr);

		std::copy_n(md.begin(), HM_LEN, K->aesKey);
		std::copy_n(md.begin() + HM_LEN, HM_LEN, K->hmacKey);

		return 0;
	}

	randBytes(K->aesKey, HM_LEN);
	randBytes(K->hmacKey, HM_LEN);

	return 0;
}
size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}
size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K, unsigned char* IV)
{
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */
	std::array<unsigned char, 16> iv = {};

	if(IV == nullptr){
		// If IV is not given get a random IV
		randBytes(iv.data(), iv.size());
		std::cout<<"generating iv"<<std::endl;
	}
	else{
		// Get the given IV
		std::copy_n(IV, iv.size(), iv.begin());
	}
	// Place IV into out buffer.
	std::copy(iv.begin(), iv.end(), outBuf);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, iv.data())) {
		ERR_print_errors_fp(stderr);
	}

	int n_written = 0;
	if(1 != EVP_EncryptUpdate(ctx, outBuf + iv.size(), &n_written, inBuf, len)) {
		ERR_print_errors_fp(stderr);
	}
	EVP_CIPHER_CTX_free(ctx);

	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, outBuf, n_written+iv.size(), 
		outBuf + n_written + iv.size(), nullptr);

	 /* TODO: should return number of bytes written, which
	    hopefully matches ske_getOutputLen(...). */
	return n_written + HM_LEN + iv.size();
}
size_t ske_encrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, unsigned char* IV, size_t offset_out){

	// Open files..
	auto fdin = open(fnin, O_RDONLY);
	auto fdout = open(fnout, O_CREAT | O_RDWR, S_IRWXU);
	if(fdin < 0 or fdout < 0) {
        std::cerr << "Failed to open file" << std::endl;
		return 0;
    }

	auto input_size = lseek(fdin, 0, SEEK_END);
	auto chunk = reinterpret_cast<unsigned char*>(mmap(nullptr, input_size,
											   		  PROT_READ, MAP_FILE | MAP_SHARED, 
											    	  fdin, 0));

	std::cout<<input_size<<std::endl;
	if(chunk == MAP_FAILED){
		std::cerr << "mmap failed" << std::endl;
		return 0;
	}
	const auto encrypted_len = ske_getOutputLen(input_size)-1; //+ 1;
	auto ciphertext = new unsigned char[encrypted_len];
	std::array<unsigned char, 16> iv = {};

	if(IV == nullptr){
		randBytes(iv.data(), iv.size());
	}
	else{
		std::copy_n(IV, iv.size(), iv.begin());
	}
	
	ske_encrypt(ciphertext, chunk, input_size, K, iv.data());

	lseek(fdout, offset_out, SEEK_SET);
	write(fdout, ciphertext, encrypted_len);
	
	munmap(chunk, input_size);
	close(fdin);
	close(fdout);

	delete[] ciphertext;
	return 0;
}
size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K){

	std::array<unsigned char, HM_LEN> hmac = {};

	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, inBuf, len-HM_LEN, hmac.data(), nullptr);

	if(not std::equal(hmac.begin(), hmac.end(), inBuf + len - HM_LEN)){
		std::cerr<<"ske_decrypt hmac signiture check failed"<<std::endl;
		return -1;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), 0, K->aesKey, inBuf)) {
		ERR_print_errors_fp(stderr);
	}
	
	int n_written = 0;
	if(1 != EVP_DecryptUpdate(ctx, outBuf, &n_written, inBuf + 16, len - HM_LEN - 16)) {
		ERR_print_errors_fp(stderr);
	}

	return n_written;
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */
}
size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in){
	
	auto fdin = open(fnin, O_RDONLY);
	auto fdout = open(fnout, O_CREAT | O_RDWR, S_IRWXU);
	if(fdin < 0 or fdout < 0) {
        std::cerr << "Failed to open file" << std::endl;
		return 0;
    }

	auto input_size = lseek(fdin, 0, SEEK_END);
	auto chunk = reinterpret_cast<unsigned char*>(mmap(nullptr, input_size,
											   		  PROT_READ, MAP_FILE | MAP_SHARED, 
											    	  fdin, 0));
	if(chunk == MAP_FAILED){
		std::cerr << "mmap failed" << std::endl;
		return 0;
	}
	const auto decrypted_len = input_size - 16 - HM_LEN - offset_in;
	auto plaintext = new unsigned char[decrypted_len];

	ske_decrypt(plaintext, chunk, input_size, K);

	lseek(fdout, 0, SEEK_SET);
	write(fdout, plaintext, decrypted_len);

	munmap(chunk, input_size);
	close(fdin);
	close(fdout);

	delete[] plaintext;

	/* TODO: write this. */
	return 0;
}
