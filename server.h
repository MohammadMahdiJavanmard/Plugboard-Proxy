#ifndef _SERVER
#define _SERVER

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <pthread.h>
#include <netdb.h>  
#include <ctype.h>

// this file contains the functionalities regarding relaying (+encryption/decryption) the information
#include "relay.h"

#define MAX_CLIENT_CONN 5

// struct definitions

struct thread_information {
    char *sshdURL;
    int sshdPort;
    int clientSocket;
    char *keyFileName;
};

// function definitions
void server(int portNumber, char *sshdURL, int sshdPort, char * keyFileName);
void *connection_handler(void *threadArg);
void *clientToSshd(void *threadArg);


// function declarations
void *clientToSshd(void *threadArg) {
	struct relay_information *relay_data;
    relay_data = (struct relay_information *) threadArg;
    
    int from = relay_data->from;
    int to = relay_data->to;
    char *iv_client = relay_data->iv;
    char *keyFileName = relay_data->keyFileName;
    struct ctr_state *dec_state = relay_data->enc_dec_state;

    relay(from, to, DECRYPT, iv_client, keyFileName, dec_state);
}

void *connection_handler(void *threadArg) {
	// GETTING THE ARGUMENTS OF THE FUNCTION FROM threadArg
	struct thread_information *thread_data;
    thread_data = (struct thread_data *) threadArg;

	int pbproxy_socket = thread_data->clientSocket;
	char *sshdURL = thread_data->sshdURL;
	int sshdPort = thread_data->sshdPort;
	char *keyFileName = thread_data->keyFileName;


	char sshdIPAddress[15]; // IPv4 can be at most 255.255.255.255
	if (hostname_to_ip(sshdURL , sshdIPAddress) == 1) {
		printf("connection_handler:: Error: Could not convert the sshd URL to the sshd IP address");
        close(pbproxy_socket);
        free(threadArg);
        return NULL;
	}

	// MAKE A SOCKET AND CONNECT TO SSHD
    int sshdSocket;
    sshdSocket = socket(AF_INET , SOCK_STREAM , 0);

    if (sshdSocket == -1) {
        printf("connection_handler:: Error: Can't make socket connection to sshd server");
        close(pbproxy_socket);
        free(threadArg);
        return NULL;
    }

    // CONNECTING TO THE REMOTE SSHD SERVER
    struct sockaddr_in sshdServer;

    sshdServer.sin_addr.s_addr = inet_addr(sshdIPAddress);
    sshdServer.sin_family = AF_INET;
    sshdServer.sin_port = htons(sshdPort);
 
    //CONNECT TO REMOTE SSHD
    if (connect(sshdSocket, (struct sockaddr *)&sshdServer, sizeof(sshdServer)) < 0)
    {
        printf("connection_handler:: Erorr: Couldn't connect to the sshd through the created socket\n");
        close(pbproxy_socket);
        free(threadArg);
        return NULL;
    }

    // NOW WE HAVE A SUCCESSFUL CONNECTION TO THE SSHD
    // the client_socket is pbproxy_socket

    unsigned char  iv_server[AES_BLOCK_SIZE];
    if(!RAND_bytes(iv_server, AES_BLOCK_SIZE))
    {
        printf("server:: Error:: can not create random bytes for initializing the iv.\n");
        fflush(stdout);
        close(pbproxy_socket);
        return;
    }


    // SENDING THE IV_SERVER TO THE PROXY-SERVER
    // source to learn: https://vcansimplify.wordpress.com/2013/03/14/c-socket-tutorial-echo-server/
    if (write(pbproxy_socket, iv_server, AES_BLOCK_SIZE) <= 0) {
    	printf("server:: Error:: can not send the IV to the proxy-client side.\n");
        fflush(stdout);
        close(pbproxy_socket);
        return;
    }


    // initiating the encryption state for server
    struct ctr_state enc_state_server;
    init_ctr(&enc_state_server, iv_server);


    // RECEIVING THE IV_CLIENT
    unsigned char  iv_client[AES_BLOCK_SIZE];
    int bytesReceived = read(pbproxy_socket, iv_client , AES_BLOCK_SIZE);
    if (bytesReceived != AES_BLOCK_SIZE) { // AES_BLOCK_SIZE is 16
    	printf("server:: Error:: Error in receiving the IV of the proxy-client side.\n");
    	fflush(stdout);
    	close(pbproxy_socket);
    	return;
    }

    // initiating the decryption state for client
    struct ctr_state dec_state_client;
    init_ctr(&dec_state_client, iv_client);

    struct relay_information *relay_data = (struct relay_information *) 
    											malloc(sizeof(struct relay_information));
    relay_data->from = pbproxy_socket;
    relay_data->to = sshdSocket;
    relay_data->iv = iv_client;
    relay_data->keyFileName = keyFileName;
    relay_data->enc_dec_state = &dec_state_client;

    // RELAYING ALL THE DATA FROM CLIENT TO SSHD + DECRYPTION
    pthread_t clientToSshd_thread;
    if( pthread_create( & clientToSshd_thread , NULL , 
        clientToSshd , (void*) relay_data) < 0) {
                printf("server:: Error::  creating clientToSshd_thread failed.\n");
                fflush(stdout);
                close(pbproxy_socket);
                free(relay_data);
                return;
    }


    // RELAYING ALL THE DATA FROM SSHD TO CLIENT + ENCRYPTION				
    // relay(int from, int to, int encrypt_decrypt, char *iv, char *keyFileName, struct ctr_state *enc_dec_state)
    relay(sshdSocket,  pbproxy_socket, ENCRYPT, iv_server, keyFileName, &enc_state_server);

    close(pbproxy_socket);
    free(relay_data);
    return;
}

void server(int portNumber, char *sshdURL, int sshdPort, char * keyFileName) {

    int server_socket , new_socket , c;
    struct sockaddr_in server, client;

    // making the socket
    server_socket = socket(AF_INET , SOCK_STREAM , 0);
    if (server_socket == -1) {
        printf("server:: Error: Could not create socket.\n");
        return;
    }

    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(portNumber); // -l 2222

    //Binding the socket to the port
    if(bind(server_socket,(struct sockaddr *)&server, sizeof(server)) < 0) {
        puts("server:: Error: Bind failed.\n");
        return;
    }


    //Listen
    listen(server_socket , MAX_CLIENT_CONN);

    //Accept the incoming connection(s)
    c = sizeof(struct sockaddr_in);
    while((new_socket = accept(server_socket,
            (struct sockaddr *)&client, (socklen_t*)&c))) {


        printf("server:: Connection request has been received.\n");
        fflush(stdout);

        pthread_t listenerThread;

        struct thread_information *thread_data = (struct thread_information *)  
            malloc (sizeof(struct thread_information));
        
        // preparing the information to be passed to the function associated with the thread
        thread_data->sshdURL = sshdURL;
        thread_data->sshdPort = sshdPort;
        thread_data->clientSocket = new_socket;
        thread_data->keyFileName = keyFileName;

        if( pthread_create( &listenerThread , NULL ,  connection_handler ,
                (void*) thread_data) < 0) {
            perror("server:: Error: could not create thread");
            close(server_socket);
            return;
        }
    }

    if (new_socket < 0) {
        perror("server:: Error: Accept failed");
        close(server_socket);
        return;
    }

    close(server_socket);
    return;
}



#endif