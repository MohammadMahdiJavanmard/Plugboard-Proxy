#ifndef _ENCRYPTION
#define _ENCRYPTION

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>	
#include <sys/socket.h>
#include <arpa/inet.h>	
#include <unistd.h>	
#include <pthread.h>
#include <netdb.h>	
#include <ctype.h>


struct ctr_state
{
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};

int read_AES_BLOCK_SIZE(char *from, char *to, int totalFromSize, int startFrom) {
    int bytesRead = 0;
    int i;
    for (i = startFrom; i < (startFrom + AES_BLOCK_SIZE) && i < totalFromSize; ++i) {
        to[i - startFrom] = from[i];
        bytesRead++;
    }
    return bytesRead;
}

// source to learn: http://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/
int encrypt(char * keyfileName, unsigned char * iv, struct ctr_state * enc_state,
	char * inputBuffer, int inputBufferSize , char * outputBuffer) {

    // FIRST READING THE KEY FROM THE FILE
    FILE * key_file = fopen(keyfileName, "rb");
    
    if(key_file == NULL) {
        printf("encrypt:: Error:: error in opening the key_file.\n");
        fflush(stdout);
        return -1;
    }
    
    unsigned char enc_key[16];
    if(fread(enc_key, 1, AES_BLOCK_SIZE, key_file) != 16) {
        printf("encrypt:: Error:: error in reading the key.\n");
        fflush(stdout);
        return -1;
    }
    fclose(key_file);
    
    //Initializing the encryption KEY
    AES_KEY key;
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0) {
        printf("encrypt:: Error:: could not set encryption key.\n");
        fflush(stdout);
        return -1;
    }
    
    int outBufCounter= 0;
    int bytesReadSoFar = 0;


    //Encrypting the data block by block
    while(bytesReadSoFar < inputBufferSize) {

        unsigned char AES_BLOCK_SIZE_Buffer[AES_BLOCK_SIZE];
        unsigned char ciphertext[AES_BLOCK_SIZE];

        int bytesRead = read_AES_BLOCK_SIZE(inputBuffer, AES_BLOCK_SIZE_Buffer,
            inputBufferSize, bytesReadSoFar);

        // AES_ctr128_encrypt(indata, outdata, bytes_read, &key, state.ivec, state.ecount, &state.num);
        AES_ctr128_encrypt(AES_BLOCK_SIZE_Buffer, ciphertext, bytesRead, &key, enc_state->ivec, enc_state->ecount, &(enc_state->num));
        
        int i;
        for(i = 0; i < bytesRead ; i++ ) {
            outputBuffer[outBufCounter + i] = ciphertext[i];
        }
        
        outBufCounter +=  bytesRead ;
        bytesReadSoFar += AES_BLOCK_SIZE;
    }       
    return outBufCounter ; 
}


int decrypt(char * keyfileName, unsigned char * iv, struct ctr_state * dec_state,
	char * inputBuffer, int inputBufferSize , char * outputBuffer) {

    // FIRST READING THE KEY FROM THE FILE
    FILE * key_file = fopen(keyfileName, "rb");
    
    if(key_file == NULL) {
        printf("decrypt:: Error:: error in opening the key_file.\n");
        fflush(stdout);
        return -1;
    }
    
    unsigned char enc_key[16];
    if(fread(enc_key, 1, AES_BLOCK_SIZE, key_file) != 16) {
        printf("decrypt:: Error:: error in reading the key.\n");
        fflush(stdout);
        return -1;
    }

    fclose(key_file);
    
    //Initializing the encryption KEY
    AES_KEY key;
    if (AES_set_encrypt_key(enc_key, 128, &key) < 0) {
        printf("decrypt:: Error:: could not set encryption key.\n");
        fflush(stdout);
        return -1;
    }
    

    int outBufCounter= 0;
    int bytesReadSoFar = 0;

    //Decrypting block by block 
    while(bytesReadSoFar < inputBufferSize) {

        unsigned char AES_BLOCK_SIZE_Buffer[AES_BLOCK_SIZE];
        unsigned char ciphertext[AES_BLOCK_SIZE];

        int bytesRead = read_AES_BLOCK_SIZE(inputBuffer, ciphertext,
            inputBufferSize, bytesReadSoFar);

        
        AES_ctr128_encrypt(ciphertext, AES_BLOCK_SIZE_Buffer, bytesRead, &key, dec_state->ivec, dec_state->ecount, &(dec_state->num));
       
        int i;
        for(i = 0; i < bytesRead ; i++ ) {
            outputBuffer[outBufCounter + i] = AES_BLOCK_SIZE_Buffer[i];
        }
        
        outBufCounter +=  bytesRead;
        bytesReadSoFar += AES_BLOCK_SIZE;
    }
    
    return outBufCounter ;    
}

#endif