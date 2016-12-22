#ifndef _RELAY
#define _RELAY

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#include "encryption.h"

#define ENCRYPT 1
#define DECRYPT 2

#define STD_OUT 1
#define STD_IN 0

#define BUFFER_SIZE 1440
#define PROCESSED_BUFFER_SIZE 1456


struct relay_information {
	int from;
	int to;
	char *iv;
	char *keyFileName;
	struct ctr_state *enc_dec_state;
};

// source to learn: http://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/
int init_ctr(struct ctr_state *state, const unsigned char iv[16]) {
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
    memset(state->ivec + 8, 0, 8);
    memcpy(state->ivec, iv, 8);
    
    return 1; 
}


int hostname_to_ip(char * hostname , char* ip) {
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
         
    if ((he = gethostbyname( hostname ) ) == NULL) 
    {
        // get the host info
        printf("hostname_to_ip:: Error:: can not convert the proxy-server URL to the proxy-server IP address\n");
        fflush(stdout);
        return 1;
    }
 
    addr_list = (struct in_addr **) he->h_addr_list;
     
    for(i = 0; addr_list[i] != NULL; i++) 
    {
        //Return the first one;
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }
     
    return 1;
}

void relay(int from, int to, int encrypt_decrypt, char *iv,
	char *keyFileName, struct ctr_state *enc_dec_state) {

	int bytesRead;
	char inputBuffer[BUFFER_SIZE];
	char processedBuffer[PROCESSED_BUFFER_SIZE];

	while (1) {
		bytesRead = read(from, inputBuffer, BUFFER_SIZE);
		if (bytesRead < 0) {
			printf("relay:: Error:: problem with reading from %d.\n", from);
			fflush(stdout);
			close(from);
			close(to);
			return;
		}

		else if (bytesRead == 0) {
			printf("relay:: connection is closed.\n");
			fflush(stdout);
			close(from);
			return;
		}
		else {
			int bytesProcessed;
			if (encrypt_decrypt == ENCRYPT) {
				bytesProcessed = encrypt(keyFileName, iv, enc_dec_state, inputBuffer, bytesRead, processedBuffer);
			}
			else if (encrypt_decrypt == DECRYPT) {
				bytesProcessed = decrypt(keyFileName, iv, enc_dec_state, inputBuffer, bytesRead, processedBuffer);
			}
				
			if (bytesProcessed < 0) {
				printf("relay:: Error:: problem with processing the input buffer.\n");
				fflush(stdout);
				close(from);
				close(to);
				return;
			}

			int bytesSentSoFar = 0;
			while (bytesSentSoFar < bytesProcessed) {
				int bytesSent = write(to, processedBuffer + bytesSentSoFar, bytesProcessed - bytesSentSoFar);
				if (bytesSent <= 0) {
					printf("relay:: Error:: problem with sending the processed messge to %d.\n", to);
					fflush(stdout);
					close(from);
					close(to);
					return;
				}

				bytesSentSoFar += bytesSent;
			}
		}
	}
}

#endif