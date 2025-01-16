#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>


int power(int base, int exp, int mod) {
    int result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1; // Equivalent to exp /= 2;
        base = (base * base) % mod;
    }
    return result;
}

int isPrimitiveRoot(int g, int p) {
    // Check if g is a primitive root modulo p
    for (int i = 1; i < p - 1; i++) {
        if (power(g, i, p) == 1) {
            return 0;
        }
    }
    return 1;
}

// Compute a^b mod c
long pow_mod(long a, long b, long c)
{
    long r;
    long y = 1;
 
    while (b > 0) {
        
        r = b % 2;
 
        if (r == 1) {
            y = (y*a) % c;
        }
        a = a*a % c;
        b = b / 2;
    }
 
    return y;
}

int evaluateGlobalVals(long p, long g, long a, long b) {
    if (p == 0 || p == 1) {
        printf("%ld is not a prime number.\n", p);
        return 0;
    }
    for (int i = 2; i <= p/2; i++) {
        // if p is divisible by i, then n is not prime
        if (p % i == 0) {
            printf("%ld is not a prime number.\n", p);
            return 0;
        }
    }

    if (!isPrimitiveRoot(g, p)) {
        printf("%ld is not a primitive root of %ld.\n", g, p);
        return 0;
    }

    if (a >= p) {
        printf("a must be less than p.\n");
        return 0;
    }

    if (b >= p) {
        printf("b must be less than p.\n");
        return 0;
    }

    return 1;
}

long generateKeys(long p, long g, long privateKey) {
   return  pow_mod(g, privateKey, p); 
}

long generateSecret(long p, long privateKey, long publicKey) {
    return pow_mod(publicKey, privateKey, p); 
}

int main(int argc, char *argv[]) {

    if (argc == 11 && strcmp(argv[1], "-o") == 0 && strcmp(argv[3], "-p") == 0 && strcmp(argv[5], "-g") == 0 && strcmp(argv[7], "-a") == 0 && strcmp(argv[9], "-b") == 0) {
        long p = strtol(argv[4], NULL, 10);
        long g = strtol(argv[6], NULL, 10);
        long a = strtol(argv[8], NULL, 10);
        long b = strtol(argv[10], NULL, 10);

        if(!evaluateGlobalVals(p, g, a, b)) {
            printf("Invalid input.\n");
            return 0;
        }
         
        srand(time(NULL));
        long A, B;

        A = generateKeys(p, g, a);
        B = generateKeys(p, g, b);
        
        // a, b: private keys
        // A, B: public keys

        printf("a = %ld\n", a);
        printf("A = %ld\n", A);
        printf("b = %ld\n", b);
        printf("B = %ld\n", B);

        long K1 = generateSecret(p, a, B);
        long K2 = generateSecret(p, b, A);
        printf("K1 = %ld\n", K1);
        printf("K2 = %ld\n", K2);

        if(K1 == K2) {
            printf("DH succeeded.\n");
            FILE *file = fopen(argv[2], "w");
            if(file == NULL) {
                printf("Unable to open file.");
                exit(0);
            }
            
            fprintf(file, "%ld, %ld, %ld", A, B, K1);
            fclose(file);

        }
    }

    else if (argc == 2 && strcmp(argv[1], "-h") == 0) {
        printf("Options:\n"
               "-o  path    Path to output file\n"
               "-p  number  Prime number\n"
               "-g  number  Primitive Root for previous prime number\n"
               "-g  length  Perform RSA key-pair generation given a key length “length”\n"
               "-a  number  Private key A\n"
               "-b  number  Private key B\n"
               "-h          This help message\n");

        printf("\nRefer to the readme file for more info on execution.\n");
    }

    else {
        printf("Error: Invalid Command!\n");
    }
    return 0;
}