#ifndef _CLIENT
#define _CLIENT

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <arpa/inet.h>	
#include <unistd.h>	
#include <pthread.h>
#include <netdb.h>	
#include <ctype.h>

// this file contains the functionalities regarding relaying (+encryption/decryption) the information
#include "relay.h"


// function headers
void client(char *serverURL, int serverPort, char *keyFileName);
void *serverToSTDOUT(void *threadArg);


// function definitions
void *serverToSTDOUT(void *threadArg) {
    struct relay_information *relay_data;
    relay_data = (struct relay_information *) threadArg;
    
    int from = relay_data->from;
    int to = relay_data->to;
    char *iv_server = relay_data->iv;
    char *keyFileName = relay_data->keyFileName;
    struct ctr_state *dec_state = relay_data->enc_dec_state;

    relay(from, to, DECRYPT, iv_server, keyFileName, dec_state);
}

void client(char *serverURL, int serverPort, char *keyFileName) {

	// converting the serverURL to the serverIP
	char serverIP[15]; // IPv4 can be at most 255.255.255.255
	if (hostname_to_ip(serverURL , serverIP) == 1) {
		printf("client:: Error:: can not convert the proxy-server URL to the proxy-server IP address\n");
		fflush(stdout);
		return;
	}

	// making the socket
	struct sockaddr_in pbproxy_server_socket_info;

	pbproxy_server_socket_info.sin_addr.s_addr = inet_addr(serverIP);
    pbproxy_server_socket_info.sin_family = AF_INET;
    pbproxy_server_socket_info.sin_port = htons(serverPort);

    // having TCP socket stream connection
    int pbproxy_socket = socket(AF_INET , SOCK_STREAM , 0);
    if (pbproxy_socket == -1) {
    	printf("client:: Error:: can not create a stream socket to connect to the server.\n");
    	fflush(stdout);
    	return;
    }

    // connecting to the proxy-server side
    if (connect(pbproxy_socket , (struct sockaddr *)&pbproxy_server_socket_info , 
    			sizeof(pbproxy_server_socket_info)) < 0) {
        printf("client:: Error:: can not connect to proxy-server side.\n");
    	fflush(stdout);
        return;
    }

    // NOW, WE HAVE A SUCCESSFUL CONNECTION TO THE PROXY-SERVER SIDE
    // the socket is pbproxy_socket

    // initializing the iv and send it to the proxy-server
    // source to learn regarding AES CTR: http://www.gurutechnologies.net/blog/aes-ctr-encryption-in-c/
    unsigned char  iv_client[AES_BLOCK_SIZE];
    if(!RAND_bytes(iv_client, AES_BLOCK_SIZE))
    {
        printf("client:: Error:: can not create random bytes for initializing the iv.\n");
        fflush(stdout);
        close(pbproxy_socket);
        return;
    }


    // SENDING THE IV_CLIENT TO THE PROXY-SERVER
    // source to learn: https://vcansimplify.wordpress.com/2013/03/14/c-socket-tutorial-echo-server/
    if (write(pbproxy_socket, iv_client, AES_BLOCK_SIZE) <= 0) {
    	printf("client:: Error:: can not send the IV to the proxy-server side.\n");
        fflush(stdout);
        close(pbproxy_socket);
        return;
    }


    // initiating the encryption state for client
    struct ctr_state enc_state_client;
    init_ctr(&enc_state_client, iv_client);

    // RECEIVING THE IV_SERVER
    unsigned char  iv_server[AES_BLOCK_SIZE];
    int bytesReceived = read(pbproxy_socket, iv_server , AES_BLOCK_SIZE);
    if (bytesReceived != AES_BLOCK_SIZE) { // AES_BLOCK_SIZE is 16
    	printf("client:: Error:: Error in receiving the IV of the proxy-server side.\n");
    	fflush(stdout);
    	close(pbproxy_socket);
    	return;
    }


    // initiating the decryption state for server
    struct ctr_state dec_state_server;
    init_ctr(&dec_state_server, iv_server);

    struct relay_information *relay_data = (struct relay_information *) 
    											malloc(sizeof(struct relay_information));
    relay_data->from = pbproxy_socket;
    relay_data->to = STD_OUT;
    relay_data->iv = iv_server;
    relay_data->keyFileName = keyFileName;
    relay_data->enc_dec_state = &dec_state_server;

    // RELAYING ALL THE DATA FROM SERVER TO STD-OUT + DECRYPTION
    pthread_t serverToSTDOUT_thread;
    if( pthread_create( & serverToSTDOUT_thread , NULL , 
        serverToSTDOUT , (void*) relay_data) < 0) {
                printf("client:: Error::  creating serverToSTDOUT_thread failed.\n");
                fflush(stdout);
                close(pbproxy_socket);
                free(relay_data);
                return;
    }

    // RELAYING ALL THE DATA FROM STD-IN TO SERVER + ENCRYPTION				
    // relay(int from, int to, int encrypt_decrypt, char *iv, char *keyFileName, struct ctr_state *enc_dec_state)
    relay(STD_IN,   pbproxy_socket, ENCRYPT, iv_client, keyFileName, &enc_state_client);

    close(pbproxy_socket);
    free(relay_data);
    return;
}


#endif