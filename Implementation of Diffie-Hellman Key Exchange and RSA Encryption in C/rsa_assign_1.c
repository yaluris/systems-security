#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <time.h>

void generateRandomPrime(mpz_t num, int l) {    
    gmp_randstate_t state;

    // Initialize random state
    gmp_randinit_default(state);
    gmp_randseed_ui(state, rand());

    // Generate random prime number
    do {
        mpz_urandomb(num, state, l);
        mpz_setbit(num, l-1);  // Ensure the number is l bits long
        mpz_setbit(num, 0);    // Sets first bit to 1 because if it's 0 the number is definitely not prime
    } while (!mpz_probab_prime_p(num, 25));  // Miller-Rabin primality test with 25 iterations
    
    gmp_randclear(state);
}

void generateRSAKeyPair(int key_length, char *publicKeyFile, char *privateKeyFile) {
    mpz_t p, q, n, psub1, qsub1, lambda, mod, gcd, e, d;

    // Initialize GMP integers
    mpz_inits(p, q, n, psub1, qsub1, lambda, mod, gcd, e, d, NULL);

    // Step 1 & 2
    generateRandomPrime(p, key_length/2);
    generateRandomPrime(q, key_length/2);
    
    // Print the generated prime numbers
    gmp_printf("p: %Zd\n", p);
    gmp_printf("q: %Zd\n", q);

    // Step 3
    mpz_mul(n, p, q);
    gmp_printf("n: %Zd\n", n);

    // Step 4
    mpz_sub_ui(psub1, p, 1);
    mpz_sub_ui(qsub1, q, 1);
    mpz_mul(lambda, psub1, qsub1);
    gmp_printf("lambda: %Zd\n", lambda);

    // Step 5
    do {
        generateRandomPrime(e, key_length/2);
        mpz_mod(mod, e, lambda);
        mpz_gcd(gcd, e, lambda);
    } while (!(mpz_cmp_ui(mod, 0) != 0 && mpz_cmp_ui(gcd, 1) == 0));
    
    gmp_printf("e: %Zd\n", e);

    // Step 6
    mpz_invert(d, e, lambda);
    gmp_printf("d: %Zd\n", d);

    // Step 7
    FILE *file;

    file = fopen(publicKeyFile, "w"); // Open the file in write mode

    if(file == NULL) {
        printf("Unable to open file.");
        exit(0);
    }

    mpz_out_str(file, 10, n);
    fprintf(file, "\n");
    mpz_out_str(file, 10, d);
    fclose(file); // Close the file

    // Step 8
    file = fopen(privateKeyFile, "w"); // Open the file in write mode
    
    if(file == NULL) {
        printf("Unable to open file.");
        exit(0);
    }

    mpz_out_str(file, 10, n);
    fprintf(file, "\n");
    mpz_out_str(file, 10, e);
    fclose(file); // Close the file

    mpz_clears(p, q, n, psub1, qsub1, lambda, mod, gcd, e, d, NULL);
}

void getKey(mpz_t n, mpz_t d_e, char *keyFile) {
    
    FILE *file = fopen(keyFile, "r");

    if(file == NULL) {
        printf("Unable to open file.");
        exit(0);
    }

    char *buffer;
    long length;

   
    fseek(file, 0, SEEK_END);
    length = ftell(file);
    fseek (file, 0, SEEK_SET);

    buffer = malloc(sizeof(char) * length + 1); //+1 to include \0
    fread(buffer, 1, length, file);
    buffer[length] = '\0';
     
    fclose(file); 

    int tmp_length = 0;
    char c;
    
    do {
        c = buffer[tmp_length];
        tmp_length++;
    }  
    while(c != '\n');

    char *n_str = malloc(sizeof(char) * tmp_length);
    strncpy(n_str, buffer, tmp_length-1);
    n_str[tmp_length] = '\0';

    char *d_e_str = buffer + tmp_length;

    printf("n_str: %s\nd_str: %s\n", n_str, d_e_str); 

    mpz_set_str (n, n_str, 10);
    mpz_set_str (d_e, d_e_str, 10);

    free(n_str);
}

void encrypt(char *inputFile, char *outputFile, char *keyFile) {
    mpz_t input, output, n, d;
    FILE *file;

    mpz_inits(input, output, n, d, NULL);

    file = fopen(inputFile, "r"); 

    if(file == NULL) {
        printf("Unable to open file.");
        exit(0);
    }

    mpz_inp_str(input, file, 10);
    fclose(file); // Close the file

    getKey(n, d, keyFile);
    
    gmp_printf("n: %Zd\n", n);
    gmp_printf("d: %Zd\n", d);

    if(mpz_cmp(input, n) < 0) {
        mpz_powm(output, input, d, n);
        gmp_printf("Encrypted message: %Zd\n", output);
        file = fopen(outputFile, "w"); // Open the file in write mode

        if(file == NULL) {
            printf("Unable to open file.");
            exit(0);
        }

        mpz_out_str(file, 10, output);
        fclose(file); // Close the file*/
    }
    else
        printf("The input text is too long.");

    mpz_clears(input, output, n, d, NULL);

} 

void decrypt(char *inputFile, char *outputFile, char *keyFile) {
    mpz_t input, output, n, e;
    FILE *file;

    mpz_inits(input, output, n, e, NULL);

    file = fopen(inputFile, "r"); 

    if(file == NULL) {
        printf("Unable to open file.");
        exit(0);
    }

    mpz_inp_str(input, file, 10);
    fclose(file); // Close the file

    getKey(n, e, keyFile);
    
    gmp_printf("n: %Zd\n", n);
    gmp_printf("e: %Zd\n", e);

    mpz_powm(output, input, e, n);
    gmp_printf("Decrypted message: %Zd\n", output);

    file = fopen(outputFile, "w"); // Open the file in write mode

    if(file == NULL) {
        printf("Unable to open file.");
        exit(0);
    }

    mpz_out_str(file, 10, output);
    fclose(file); // Close the file*/

    mpz_clears(input, output, n, e, NULL);
}

void perfomanceAssessment(int key_length, char *performance, char *publicKeyFile, char *privateKeyFile) {
        
    srand(time(NULL));

    generateRSAKeyPair(key_length, publicKeyFile, privateKeyFile);
        
    clock_t begin1 = clock();
    encrypt("plaintext.txt", "ciphertext.txt", publicKeyFile);
    clock_t end1 = clock();
    double time_spent1 = (double)(end1 - begin1) / CLOCKS_PER_SEC;

    clock_t begin2 = clock();
    decrypt("ciphertext.txt", "deciphertext.txt", privateKeyFile);
    clock_t end2 = clock();    
    double time_spent2 = (double)(end2 - begin2) / CLOCKS_PER_SEC;

    double total_time = time_spent1 + time_spent2;
    
    printf("Time spent1: %lf seconds\n", time_spent1);
    printf("Time spent2: %lf seconds\n", time_spent2);
    printf("Total time spent: %lf seconds\n", total_time);

    FILE *file = fopen(performance, "a"); //Open the file in append mode

    if(file == NULL) {
        printf("Unable to open file.");
        exit(0);
    }

    fprintf(file, "Key Length: %d\nEncryption performance: %lf seconds\nDecryption performance: %lf seconds\nTotal time: %lf seconds\n\n", key_length, time_spent1, time_spent2, total_time);
    fclose(file); // Close the file*/
}


int main(int argc, char *argv[]) {
    if (argc == 3 && strcmp(argv[1], "-g") == 0) {
        srand(time(NULL));
        generateRSAKeyPair(atoi(argv[2]), "public_length.key", "private_length.key");
    } 
    else if (argc == 8 && strcmp(argv[1], "-i") == 0 && strcmp(argv[3], "-o") == 0 && strcmp(argv[5], "-k") == 0 && strcmp(argv[7], "-e") == 0) {
        encrypt(argv[2], argv[4], argv[6]);
    } 
    else if (argc == 8 && strcmp(argv[1], "-i") == 0 && strcmp(argv[3], "-o") == 0 && strcmp(argv[5], "-k") == 0 && strcmp(argv[7], "-d") == 0) {
        decrypt(argv[2], argv[4], argv[6]);
    } 
    else if (argc == 3 && strcmp(argv[1], "-a") == 0) {
        remove(argv[2]);
        perfomanceAssessment(1024, argv[2], "public_1024.key", "private_1024.key");
        perfomanceAssessment(2048, argv[2], "public_2048.key", "private_2048.key");
        perfomanceAssessment(4096, argv[2], "public_4096.key", "private_4096.key");
    }
    else if (argc == 2 && strcmp(argv[1], "-h") == 0) {
        printf("Options:\n"
               "-i  path    Path to the input file\n"
               "-o  path    Path to the output file\n"
               "-k  path    Path to the key file\n"
               "-g  length  Perform RSA key-pair generation given a key length “length”\n"
               "-d          Decrypt input and store results to output.\n"
               "-e          Encrypt input and store results to output.\n"
               "-a          Compare the performance of RSA encryption and decryption with three\n"
               "            different key lengths (1024, 2048, 4096 key lengths) in terms of computational time.\n"
               "-h          This help message\n");

        printf("\nRefer to the readme file for more info on execution.\n");
    }
    else {
        printf("Error: Invalid Command!\n");
    }
    
    return 0;
}