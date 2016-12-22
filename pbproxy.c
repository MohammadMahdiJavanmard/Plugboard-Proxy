#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "server.h"
#include "client.h"


int main(int argc, char **argv) {

	int kFlag = 0;
	int lFlag = 0;

	char *keyFileName;
	char dashK[] = "-k";
	char dashL[] = "-l";

	// the first argument (index 0) is the name of the executable file. Skipping ...
	int counter = 1;

	// generating the key ==> 3 arguments
	// pbproxy -k mykey
	if (argc == 3) { 
		if (strcmp(dashK, argv[counter]) == 0) {
			kFlag = 1;
			counter++; // counter is 2
			keyFileName = argv[counter];
			
			// generating key, encryption, decryption were learned from here:
			// http://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/

			// generating a random key
			FILE *keyFile;
			unsigned char keyRandomBytes[AES_BLOCK_SIZE];
			if(!RAND_bytes(keyRandomBytes, AES_BLOCK_SIZE)) {
		        printf("pbproxy:: Error:: Could not create the key (random bytes).");
		    	fflush(stdout);    
		        exit(EXIT_FAILURE);
    		}

    		keyFile = fopen(keyFileName, "wb");
    		// making the key
    		fwrite(keyRandomBytes, 1, AES_BLOCK_SIZE, keyFile);
    		fclose(keyFile);
    		return EXIT_SUCCESS;
		}
		else {
			printf("pbproxy:: Error:: [generating the key] The program's first argument must be -k\n");
			fflush(stdout);
			exit(EXIT_FAILURE);
		}
	}

	// client call ==> 5 arguments
	// pbproxy -k mykey vuln.cs.stonybrook.edu 2222
	else if (argc == 5) {
		if (strcmp(dashK, argv[counter]) == 0) {
			kFlag = 1;
			counter++;
			keyFileName = argv[counter];
			counter++;

			char *serverURL = argv[counter]; // vuln.cs.stonybrook.edu
			counter++;

			int serverPort = atoi(argv[counter]); // 2222
			counter++;

			//printf("Client side has been called with information -k: %s, serverURL: %s, serverPort: %d\n", keyFileName, serverURL, serverPort);
			client(serverURL, serverPort, keyFileName);
			return EXIT_SUCCESS;
		}
		else {
			printf("pbproxy:: Error:: [calling client side of  the proxy] The program's first argument must be -k\n");
			fflush(stdout);
			exit(EXIT_FAILURE);
		}
	}

	// server call ==> 7 arguments
	// pbproxy -k mykey -l 2222 localhost 22
	else if (argc == 7) {
		if (strcmp(dashK, argv[counter]) == 0) {
			kFlag = 1;
			counter++;
			keyFileName = argv[counter];
			counter++;

			if (strcmp(dashL, argv[counter]) == 0) {
				// server call
				// 2222 localhost 22
				counter++;
				int serverPort = atoi(argv[counter]); // 2222
				counter++;

				char *sshdURL = argv[counter]; //localhost
				counter++;

				int sshdPort = atoi(argv[counter]); // 22
				counter++;

				//printf("Server side has been called with information -k: %s, -l: %d, sshdURL: %s, sshdPort: %d\n", keyFileName, serverPort, sshdURL, sshdPort);
				server(serverPort, sshdURL, sshdPort, keyFileName);

				return EXIT_SUCCESS;
			}
			else {
				printf("pbproxy:: Error:: [calling server side of  the proxy] The program's second argument must be -l\n");
				fflush(stdout);
				exit(EXIT_FAILURE);
			}
		}
		else {
			printf("pbproxy:: Error:: [calling server side of  the proxy] The program's first argument must be -k\n");
			fflush(stdout);
			exit(EXIT_FAILURE);
		}
	}
}
