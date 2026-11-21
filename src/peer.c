#include <arpa/inet.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./common.h"
#include "./peer.h"

// Global variables to be used by both the server and client side of the peer.
Address_t *my_address;
NetworkRecord_t networkRecord;

void print_network_record() {
  printf("--------------------------\n");
  printf("Printing Network Record:\n");
  printf("peers: %d\n", networkRecord.peer_count);
  printf("max size: %d\n", networkRecord.max_size);
  for (uint32_t i = 0; i < networkRecord.peer_count; i++) {
    printf("\t%s:%d salt: %s signature: %s\n", networkRecord.network[i]->ip,
           networkRecord.network[i]->port, networkRecord.network[i]->salt,
           networkRecord.network[i]->signature);
  }
  printf("--------------------------\n");
}
/*
 * checks if an address already exists in the network
 * only compares ip:port
 */
bool addressExistsInNetwork(Address_t *pa) {
  for (uint j = 0; j < networkRecord.peer_count; j++) {
    bool sameIp = memcmp(networkRecord.network[j]->ip, pa->ip, IP_LEN);
    bool samePort = networkRecord.network[j]->port == pa->port;

    if (sameIp && samePort) {
      return true;
    }
  }
  return false;
}

void storePeer(Address_t *pa) {
  if (addressExistsInNetwork(pa)) {
    printf("%s:%d was not added as it already existed.\n", pa->ip, pa->port);
    return;
  }
  // Increasing network array size
  if (networkRecord.max_size == networkRecord.peer_count) {
    Address_t **new_network =
        malloc(sizeof(Address_t *) * networkRecord.max_size * 2);

    if (!new_network) {
      printf("failed to malloc new_network\n");
      return;
    }

    memcpy(new_network, networkRecord.network,
           sizeof(Address_t *) * networkRecord.max_size);
    networkRecord.max_size *= 2;
    free(networkRecord.network);
    networkRecord.network = new_network;
  }
  // TODO: decreasing size
  //
  // add to "network"
  networkRecord.network[networkRecord.peer_count] = pa;

  // update "peer_count"
  networkRecord.peer_count += 1;
}
/*
 * Send a request message to another peer on the network. Unless this is
 * specifically an 'inform' message as described in the assignment handout, a
 * reply will always be expected.
 */
void send_message(Address_t peer_address, int command, char *request_body,
                  int body_length) {
  fprintf(stdout, "Connecting to server at %s:%d to run command %d\n",
          peer_address.ip, peer_address.port, command);

  compsys_helper_state_t state;
  char msg_buf[MAX_MSG_LEN];
  FILE *fp;

  // Setup connection. Note that we need to convert our port from an integer
  // to a string
  char port_char[6];
  port_char[5] = '\0';
  sprintf(port_char, "%d", peer_address.port);
  int peer_socket = compsys_helper_open_clientfd(peer_address.ip, port_char);
  compsys_helper_readinitb(&state, peer_socket);

  // Construct a request message and send it to the peer
  struct RequestHeader request_header;
  strncpy(request_header.ip, my_address->ip, IP_LEN);
  memcpy(request_header.signature, my_address->signature, SHA256_HASH_SIZE);
  request_header.port = htonl(my_address->port);
  request_header.command = htonl(command);
  request_header.length = htonl(body_length);
  // Copy the header and body together to the message buffer, then write to
  // the socket
  memcpy(msg_buf, &request_header, REQUEST_HEADER_LEN);
  memcpy(msg_buf + REQUEST_HEADER_LEN, request_body, body_length);
  compsys_helper_writen(peer_socket, msg_buf, REQUEST_HEADER_LEN + body_length);

  /*
  3: Handing the response to the register message
  Rather than closing immediately we should probably handle a response.
  */
  ReplyHeader_t reply_header;
  compsys_helper_readn(peer_socket, &reply_header, REPLY_HEADER_LEN);

  reply_header.length = ntohl(reply_header.length);
  reply_header.status = ntohl(reply_header.status);
  reply_header.this_block = ntohl(reply_header.this_block);
  reply_header.block_count = ntohl(reply_header.block_count);

  // guard rails (<0 is unneccessary, as its a uint (Max removed it))
  if (reply_header.length > MAX_MSG_LEN - REPLY_HEADER_LEN) {
    printf("incomming reply length greater than allowed\n");
    return;
  }

  if (reply_header.status != STATUS_OK) {
    printf("error! received status: %d\n", reply_header.status);
    return;
  }

  // get total response
  char responseBodyBuffer[reply_header.length];
  compsys_helper_readn(peer_socket, responseBodyBuffer, reply_header.length);

  // recalculate block hash
  hashdata_t calculatedBlockHash;
  get_data_sha(responseBodyBuffer, calculatedBlockHash, reply_header.length,
               SHA256_HASH_SIZE);

  // throw error if mismatch
  if (memcmp(reply_header.block_hash, calculatedBlockHash, SHA256_HASH_SIZE) !=
      0) {
    // TODO: Maybe actually throw error?
    printf("wrong blockhash. disregarding.\n");
    return;
  }

  // TODO: Baseline to calculate total hash, as it is the hash of all blocks,
  // but we only can load one for now.
  // -> It was built on the idea, that the whole reply was the "total hash", but
  // that is wrong. So changes are necessary. save total hash (4+4+4+4+32=48)
  //
  // // recalculate total hash
  // char *totalResponse = malloc(REPLY_HEADER_LEN+reply_length); // todo: needs
  // to be freed somewhere if (!totalResponse) {
  //     return;
  // }
  // memcpy(totalResponse, reply_header, REPLY_HEADER_LEN); //first write
  // response header memcpy(&totalResponse[REPLY_HEADER_LEN],
  // responseBodyBuffer, reply_length); //then write response body

  // hashdata_t calculatedTotalHash;
  // get_data_sha(totalResponse, calculatedTotalHash,
  // reply_length+REPLY_HEADER_LEN, SHA256_HASH_SIZE);

  // // throw error if mismatch
  // if (memcmp(sentTotalHash, calculatedTotalHash, SHA256_HASH_SIZE) != 0) {
  //     // TODO: Maybe actually throw error?
  //     printf("wrong total hash. disregarding.\n");
  //     return;
  // }

  printf("reply length: %d\n", reply_header.length);

  if (command == COMMAND_REGISTER) {
    int newPeersCount = reply_header.length / PEER_ADDR_LEN;
    printf("Incomming peers: %d\n", newPeersCount);

    // we could optimize this to O(n) instead of O(m*n), by checking all new
    // peers for duplicates and comparing to network without inserting, and then
    // inserting at last. however, I choose to do it simpler.
    for (int i = 0; i < newPeersCount; i++) {
      // load peer data as address
      Address_t *pa = malloc(sizeof(Address_t));
      if (!pa) {
        printf("malloc of peer address failed\n");
        return;
      }
      memcpy(pa, responseBodyBuffer + i * PEER_ADDR_LEN, PEER_ADDR_LEN);
      pa->port = ntohl(pa->port);

      if (is_valid_ip(pa->ip) != 1) {
        printf("Peer does not have a valid IP: %s\n", request_header.ip);
      }

      if (is_valid_port(pa->port) != 1) {
        printf("Peer does not have a valid port: %d\n", request_header.port);
      }

      pthread_mutex_lock(&networkRecord.mutex);
      storePeer(pa);
      pthread_mutex_unlock(&networkRecord.mutex);

      // ignore if they already exist in "network"
    }
  }

  close(peer_socket);
}

/*
 * Function to act as thread for all required client interactions. This thread
 * will be run concurrently with the server_thread. It will start by requesting
 * the IP and port for another peer to connect to. Once both have been provided
 * the thread will register with that peer and expect a response outlining the
 * complete network. The user will then be prompted to provide a file path to
 * retrieve. This file request will be sent to a random peer on the network.
 * This request/retrieve interaction is then repeated forever.
 */
void *client_thread() {
  char peer_ip[IP_LEN];
  fprintf(stdout, "Enter peer IP to connect to: ");
  scanf("%16s", peer_ip);

  // Clean up IP string as otherwise some extra chars can sneak in.
  for (int i = strlen(peer_ip); i < IP_LEN; i++) {
    peer_ip[i] = '\0';
  }

  char peer_port[PORT_STR_LEN];
  fprintf(stdout, "Enter peer port to connect to: ");
  scanf("%16s", peer_port);

  // Clean up Port string as otherwise some extra chars can sneak in.
  for (int i = strlen(peer_port); i < PORT_STR_LEN; i++) {
    peer_port[i] = '\0';
  }

  Address_t peer_address;
  memcpy(peer_address.ip, peer_ip, IP_LEN);
  peer_address.port = atoi(peer_port);

  /*
  2: Sending a first register message
  Here you should probably send a first register message using the
  send_message function.
  */

  send_message(peer_address, COMMAND_REGISTER, NULL, 0);
  pthread_mutex_lock(&networkRecord.mutex);
  print_network_record();
  pthread_mutex_unlock(&networkRecord.mutex);

  // You should never see this printed in your finished implementation
  printf("Client thread done\n");

  return NULL;
}

/*
 * Handler for all server requests. This will call the relevent function based
 * on the parsed command code
 */

void handle_register_request() { return; }

void *handle_server_request_thread(void *vargp) {
  char buf[MAXLINE];
  compsys_helper_state_t state;

  int connfd = *((int *)vargp);
  pthread_detach(pthread_self());
  free(vargp);

  /*
  5: Reading Server Requests
  Here we should probable actually read in some input data.
  */

  RequestHeader_t request_header;
  compsys_helper_readn(connfd, &request_header, REQUEST_HEADER_LEN);

  request_header.port = ntohl(request_header.port);
  request_header.command = ntohl(request_header.command);
  request_header.length = ntohl(request_header.length);

  if (request_header.length > MAX_MSG_LEN - REPLY_HEADER_LEN) {
    printf("incomming reply length greater than allowed\n");
    return NULL;
  }

  if (is_valid_ip(request_header.ip) != 1) {
    printf("Not a valid IP: %s\n", request_header.ip);
  }

  if (is_valid_port(request_header.port) != 1) {
    printf("Not a valid port: %d\n", request_header.port);
  }

  if (request_header.command > 3) {
    printf("Not a valid command: %d\n", request_header.command);
  }

  char requestBodyBuffer[request_header.length];
  compsys_helper_readn(connfd, requestBodyBuffer, request_header.length);

  printf("Received request from %s:%d\n", request_header.ip,
         request_header.port);

  close(connfd);
  return NULL;
}

/*
 * Function to act as basis for running the server thread. This thread will be
 * run concurrently with the client thread, but is infinite in nature.
 */
void *server_thread() {
  int listenfd;

  // Start listening
  char port_char[6];
  port_char[5] = '\0';
  sprintf(port_char, "%d", my_address->port);
  listenfd = compsys_helper_open_listenfd(port_char);

  /*
  4: Setting Up Server Threading
  Here we should implement some sort of loop to accept inbound communications
  and handle them within a thread so they do not block subsequent
  connections. The function 'handle_server_request_thread' has been provided
  as a simple skeleton function you could use to process your requests in.
  */
  // Code taken from lecture 26.10.26 (multithreaded server)

  // Setup variables for handdeling threads:
  int *connfdp;
  pthread_t tid;

  while (1) {
    connfdp = malloc(sizeof(int));
    // currently not storing client address
    *connfdp = accept(listenfd, NULL, NULL);
    pthread_create(&tid, NULL, handle_server_request_thread, connfdp);
  }

  // You should never see this printed in your finished implementation
  printf("Server thread done\n");

  return NULL;
}

int main(int argc, char **argv) {
  // Users should call this script with a single argument describing what
  // config to use
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <IP> <PORT>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  my_address = (Address_t *)malloc(sizeof(Address_t));
  memset(my_address->ip, '\0', IP_LEN);
  memcpy(my_address->ip, argv[1], strlen(argv[1]));
  my_address->port = atoi(argv[2]);

  if (!is_valid_ip(my_address->ip)) {
    fprintf(stderr, ">> Invalid peer IP: %s\n", my_address->ip);
    exit(EXIT_FAILURE);
  }

  if (!is_valid_port(my_address->port)) {
    fprintf(stderr, ">> Invalid peer port: %d\n", my_address->port);
    exit(EXIT_FAILURE);
  }

  char password[PASSWORD_LEN];
  fprintf(stdout, "Create a password to proceed: ");
  scanf("%16s", password);

  // Clean up password string as otherwise some extra chars can sneak in.
  for (int i = strlen(password); i < PASSWORD_LEN; i++) {
    password[i] = '\0';
  }

  // Most correctly, we should randomly generate our salts, but this can make
  // repeated testing difficult so feel free to use the hard coded salt below
  char user_salt[SALT_LEN + 1] = "0123456789ABCDEF\0";
  // generate_random_salt(user_salt);
  memcpy(my_address->salt, user_salt, SALT_LEN);

  /*
  1: Setting Up
  After determining our salt but before saving our address we should probably
  work out what our signature should be.
  */
  get_signature(password, strlen(password), user_salt,
                (hashdata_t *)(my_address->signature));
  // todo: maybe error handle if this fails? if it fails, it's likely because of
  // the malloc failing inside get_signature

  // Start our record of the network by recording our own address. Make sure
  // any time we update this array we also update the peer_count.
  networkRecord.network = malloc(sizeof(Address_t *));
  networkRecord.network[0] = my_address;
  networkRecord.peer_count = 1;
  networkRecord.max_size = 1;
  pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  networkRecord.mutex = mutex;

  // Setup the client and server threads
  pthread_t client_thread_id;
  pthread_t server_thread_id;
  pthread_create(&server_thread_id, NULL, server_thread, NULL);
  printf("Starting to listen on %s:%d\n", my_address->ip, my_address->port);
  pthread_create(&client_thread_id, NULL, client_thread, NULL);

  // Wait for them to complete.
  pthread_join(client_thread_id, NULL);
  pthread_join(server_thread_id, NULL);

  exit(EXIT_SUCCESS);
}
