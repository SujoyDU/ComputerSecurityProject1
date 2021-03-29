#include <iostream>
#include <fstream>

#include <gmp.h>


unsigned long int random_seed(){

    // Get random seed
    //Declare value to store seed into
    unsigned long int seed = 0;

    //Open stream
    std::ifstream urandom("/dev/urandom", std::ios::in|std::ios::binary); 

    if(not urandom){

        std::cerr << "Failed to open /dev/urandom" << std::endl;
        return 0;
    }
    //Read from urandom
    urandom.read(reinterpret_cast<char*>(&seed), sizeof(seed)); 

    // Check if stream is ok, read succeeded
    if(not urandom){
    
        std::cerr << "Failed to read from /dev/urandom" << std::endl;
        return 0;
    }
    // close stream
    urandom.close();

    return seed;
}
/**
 * Generate random prime on n bits.
 * 2^(n-1) <= p <= 2^n - 1
 * Use /dev/urandom to generate seed.
 * @param result Reference to save the generated prime.
 * @param bit_len Lenght of the random prime in bits.
 * @param resp A composite number will be identified as a prime 
 *             with an asymptotic probability of less than 4^(-reps).
 * @return Non zero value on success.  
 */
unsigned int randomprime(mpz_t result, unsigned int bit_len, unsigned int resp){

    const auto seed = random_seed();

    // Random int of n bits.
    mpz_t mpz_int;
    gmp_randstate_t state;
    mpz_init(mpz_int);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, seed);
    mpz_rrandomb(mpz_int, state, bit_len);

    // Initialize mpz_max_allowed_int=2^bit_len - 1
    mpz_t mpz_max_allowed_int;
    mpz_init(mpz_max_allowed_int);
    mpz_ui_pow_ui(mpz_max_allowed_int, 2, bit_len);
    mpz_sub_ui(mpz_max_allowed_int, mpz_max_allowed_int, 1);

    // Initialize mpz_min_allowed_int=2^(bit_len - 1)
    mpz_t mpz_min_allowed_int;
    mpz_init(mpz_min_allowed_int);
    mpz_ui_pow_ui(mpz_min_allowed_int, 2, bit_len - 1);
    mpz_add_ui(mpz_min_allowed_int, mpz_min_allowed_int, 1); // add 1 to make odd.

    // Make sure mpz_int is odd.
    if(mpz_even_p(mpz_int)){

        mpz_add_ui(mpz_int, mpz_int, 1);
    }

    // We can't blindly use gmp's next_prime function because depending on the
    // random number generated, next_prime might not fit in n bits.
    while(true){

        if(mpz_probab_prime_p(mpz_int, resp)){

            std::cout<<"Random prime generated:"<<std::endl;
            std::cout<<mpz_get_str(nullptr, 10, mpz_int)<<std::endl;

            mpz_set(result, mpz_int);
            return 1;
        }
        // mpz_int += 2
        mpz_add_ui(mpz_int, mpz_int, 2);

        // If mpz_int reached the max amount length in n_bits
        if(mpz_cmp(mpz_int, mpz_max_allowed_int) > 0){
            
            // Reset mpz_int to 2^(n_bits-1) + 1
            mpz_set(mpz_int, mpz_min_allowed_int);
        }
    }

    return 0;
}

void randomcoprime(mpz_t result, mpz_t op){

    const auto seed = random_seed();

    // Random odd int of n bits.
    mpz_t rand_int;
    gmp_randstate_t state;
    mpz_init(rand_int);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, seed);

    mpz_urandomm(rand_int, state, op);

    while(true){

        mpz_t gcd;
        mpz_init(gcd);
        mpz_gcd(gcd, rand_int, op);

        // if gcd(rand_int, op) == 1
        if(mpz_cmp_ui(gcd, 1) == 0){

            mpz_set(result, rand_int);
            return;
        }
        
        mpz_add_ui(rand_int, rand_int, 1);

        // If rand_int == op
        if(mpz_cmp(rand_int, op) == 0){

            mpz_urandomm(rand_int, state, op);
        }
    }
}