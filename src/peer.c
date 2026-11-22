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
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#else
#include <endian.h>
#endif

#include "./common.h"
#include "./peer.h"
#include "./sha256.h"

// Global variables to be used by both the server and client side of the peer.
Address_t *my_address;
NetworkRecord_t networkRecord;     // all addresses in network signature
ProcessingFiles_t processingFiles; // all files currently being processed

// calls need to be inside processing files mutex
int add_processing_files(char *file_name) {

  // grow file name array if needed
  if (processingFiles.max_size == processingFiles.current_size) {
    char **new_file_names =
        malloc(sizeof(char *) * processingFiles.max_size * 2);

    if (!new_file_names) {
      printf("failed to malloc new_file_names\n");
      return 0;
    }

    memcpy(new_file_names, processingFiles.file_names,
           sizeof(char *) * processingFiles.max_size);
    processingFiles.max_size *= 2;
    free(processingFiles.file_names);
    processingFiles.file_names = new_file_names;
  }

  // malloc new file name
  char *fptr = malloc(sizeof(char) * strlen(file_name));
  strcpy(fptr, file_name);
  if (!fptr) {
    printf("failed to malloc the file name\n");
    return 0;
  }
  processingFiles.file_names[processingFiles.current_size] = fptr;
  processingFiles.current_size++;
  return 1;
}

// calls need to be inside processing files mutex
int remove_processing_file(char *file_name) {
  // find and free file name
  for (uint i = 0; i < processingFiles.current_size; i++) {
    if (strcmp(file_name, processingFiles.file_names[i]) == 0) {
      free(processingFiles.file_names[i]);
      for (uint j = i + 1; j < processingFiles.current_size; j++) {
        processingFiles.file_names[j - 1] = processingFiles.file_names[j];
      }
    }
  }
  // shrink array if needed
  if (processingFiles.max_size >= processingFiles.current_size * 4) {

    char **new_file_names =
        malloc(sizeof(char *) * processingFiles.current_size * 2);

    if (!new_file_names) {
      printf("failed to malloc new_file_names\n");
      return 0;
    }

    memcpy(new_file_names, processingFiles.file_names,
           sizeof(char *) * processingFiles.current_size * 2);
    processingFiles.max_size = processingFiles.current_size * 2;
    free(processingFiles.file_names);
    processingFiles.file_names = new_file_names;
  }
  return 1;
}

// calls need to be inside processing files mutex
int is_file_being_processed(char *file_name) {
  for (uint i = 0; i < processingFiles.current_size; i++) {
    if (strcmp(file_name, processingFiles.file_names[i]) == 0) {
      return 1;
    }
  }

  return 0;
}

// calls need to be inside network mutex
void print_address(Address_t *a) {
  char signature[SHA256_HASH_SIZE];
  memcpy(signature, a->signature, SHA256_HASH_SIZE);
  printf("\t%s:%d salt: %.*s signature: %.*s\n", a->ip, a->port, SALT_LEN,
         a->salt, SHA256_HASH_SIZE, signature);
}

// calls need to be inside network mutex
Address_t *get_random_peer() {
  if (networkRecord.peer_count <= 1) {
    printf("Tried to retrieve random peer, however network size is: %d\n",
           networkRecord.peer_count);
    return NULL;
  }
  while (1) {
    uint32_t i = rand() % networkRecord.peer_count;
    int is_it_me =
        (memcmp(networkRecord.network[i], my_address, IP_LEN + PORT_LEN) == 0);
    if (!is_it_me) {
      return networkRecord.network[i];
    }
  }
}

// calls need to be inside network mutex
void print_network_record() {
  printf("--------------------------\n");
  printf("Printing Network Record:\n");
  printf("peers: %d\n", networkRecord.peer_count);
  printf("max size: %d\n", networkRecord.max_size);
  for (uint32_t i = 0; i < networkRecord.peer_count; i++) {
    print_address(networkRecord.network[i]);
  }
  printf("--------------------------\n");
}
/*
 * checks if an address already exists in the network
 * only compares ip:port
 */
// calls need to be inside network mutex
Address_t *get_peer(Address_t *pa) {
  for (uint i = 0; i < networkRecord.peer_count; i++) {
    int sameIp = memcmp(networkRecord.network[i]->ip, pa->ip, IP_LEN) == 0;
    int samePort = networkRecord.network[i]->port == pa->port;

    if (sameIp && samePort) {
      return networkRecord.network[i];
    }
  }
  return NULL;
}

// calls need to be inside network mutex
int storePeer(Address_t *pa) {
  if (get_peer(pa)) {
    printf("%s:%d was not added as it already existed.\n", pa->ip, pa->port);
    return STATUS_PEER_EXISTS;
  }
  // Increasing network array size
  if (networkRecord.max_size == networkRecord.peer_count) {
    Address_t **new_network =
        malloc(sizeof(Address_t *) * networkRecord.max_size * 2);

    if (!new_network) {
      printf("failed to malloc new_network\n");
      return STATUS_OTHER;
    }

    memcpy(new_network, networkRecord.network,
           sizeof(Address_t *) * networkRecord.max_size);
    networkRecord.max_size *= 2;
    free(networkRecord.network);
    networkRecord.network = new_network;
  }
  // add to "network"
  Address_t *network_entry = malloc(sizeof(Address_t));
  if (!network_entry) {
    printf("failed to malloc network_entry\n");
    return STATUS_OTHER;
  }
  memcpy(network_entry, pa, sizeof(Address_t));
  networkRecord.network[networkRecord.peer_count] = network_entry;

  // update "peer_count"
  networkRecord.peer_count += 1;
  return STATUS_OK;
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

  // return early as we don't expect an answer
  if (command == COMMAND_INFORM) {
    close(peer_socket);
    return;
  }

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

  printf("new response: block_count is %d\n", reply_header.block_count);

  // guard rails (<0 is unneccessary, as its a uint (Max removed it))
  if (reply_header.length > MAX_MSG_LEN - REPLY_HEADER_LEN) {
    printf("incomming reply length greater than allowed: %u\n",
           reply_header.length);
    close(peer_socket);
    return;
  }

  if (reply_header.status != STATUS_OK &&
      reply_header.status != STATUS_PEER_EXISTS) {
    printf("error! received status: %d\n", reply_header.status);
    close(peer_socket);
    return;
  }

  // get total response
  char responseBodyBuffer[reply_header.block_count *
                              (MAX_MSG_LEN - REPLY_HEADER_LEN) +
                          1];
  int totalLength = 0;

  for (uint i = 0; i < reply_header.block_count; i++) {
    if (i > 0) {
      compsys_helper_readn(peer_socket, &reply_header, REPLY_HEADER_LEN);
      reply_header.length = ntohl(reply_header.length);
      reply_header.status = ntohl(reply_header.status);
      reply_header.this_block = ntohl(reply_header.this_block);
      reply_header.block_count = ntohl(reply_header.block_count);
    }
    totalLength += reply_header.length;

    printf("successfully read block (%d / %d). Block size is %d. Total length "
           "is: %d\n",
           reply_header.this_block, reply_header.block_count - 1,
           reply_header.length, totalLength);

    // get response block
    char BlockBodyBuffer[reply_header.length];
    compsys_helper_readn(peer_socket, BlockBodyBuffer, reply_header.length);

    // copy data to total response
    memcpy(responseBodyBuffer +
               reply_header.this_block * (MAX_MSG_LEN - REPLY_HEADER_LEN),
           BlockBodyBuffer, reply_header.length);

    // recalculate block hash
    hashdata_t calculatedBlockHash;
    get_data_sha(BlockBodyBuffer, calculatedBlockHash, reply_header.length,
                 SHA256_HASH_SIZE);

    // throw error if mismatch
    if (memcmp(reply_header.block_hash, calculatedBlockHash,
               SHA256_HASH_SIZE) != 0) {
      printf("wrong blockhash. disregarding.\n");
      close(peer_socket);
      return;
    }
  }

  hashdata_t calculatedTotalHash;
  get_data_sha(responseBodyBuffer, calculatedTotalHash, totalLength,
               SHA256_HASH_SIZE);

  // throw error if mismatch
  if (memcmp(reply_header.total_hash, calculatedTotalHash, SHA256_HASH_SIZE) !=
      0) {
    printf("wrong total hash. disregarding.\n");
    close(peer_socket);
    return;
  }

  if (command == COMMAND_REGISTER) {
    int newPeersCount = totalLength / PEER_ADDR_LEN;
    printf("Incomming peers: %d\n", newPeersCount);

    // we could optimize this to O(n) instead of O(m*n), by checking all new
    // peers for duplicates and comparing to network without inserting, and then
    // inserting at last. however, I choose to do it simpler.
    for (int i = 0; i < newPeersCount; i++) {
      // load peer data as address
      Address_t pa;
      memcpy(&pa, responseBodyBuffer + i * PEER_ADDR_LEN, PEER_ADDR_LEN);
      pa.port = ntohl(pa.port);

      if (is_valid_ip(pa.ip) != 1) {
        printf("Peer does not have a valid IP: %s\n", request_header.ip);
      }

      if (is_valid_port(pa.port) != 1) {
        printf("Peer does not have a valid port: %d\n", request_header.port);
      }

      pthread_mutex_lock(&networkRecord.mutex);
      storePeer(&pa);
      pthread_mutex_unlock(&networkRecord.mutex);

      // ignore if they already exist in "network"
    }
  }
  // https://www.w3schools.com/c/c_files.php
  if (command == COMMAND_RETREIVE) {

    // save copy of file name and make sure it is terminated
    char file_name[body_length + 1];
    memcpy(file_name, request_body, body_length);
    file_name[body_length] = '\0';

    pthread_mutex_lock(&processingFiles.mutex);
    if (!is_file_being_processed(file_name)) {
      if (!add_processing_files(file_name)) {
        printf("was unable to store file: %s to currently processed files\n",
               file_name);
        close(peer_socket);
        pthread_mutex_unlock(&processingFiles.mutex);
        return;
      }
    }
    pthread_mutex_unlock(&processingFiles.mutex);
    // zero-indexed, so final byte is just null byte. this is for printing the
    // files primarily.
    responseBodyBuffer[totalLength] = '\0';

    fp = fopen(request_body, "w");
    if (!fp) {
      printf("Error creating file: %s", file_name);
      close(peer_socket);
      return;
    }
    int bytes_written = fprintf(fp, "%s", responseBodyBuffer);
    fclose(fp);

    pthread_mutex_lock(&processingFiles.mutex);
    remove_processing_file(file_name);
    pthread_mutex_unlock(&processingFiles.mutex);

    if (bytes_written < totalLength - 1) {
      printf("Error writing file: %s, wrote %d / %d bytes", file_name,
             bytes_written, totalLength - 1);
      close(peer_socket);
      return;
    }
    printf("Successfully received %s with length %d\n", file_name,
           totalLength - 1);
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

  while (1) {
    char file_path[MAX_FILE_PATH_LEN]; // common on most systems
    fprintf(stdout, "Enter file to retrieve: ");
    scanf("%255s", file_path);

    // Clean up file name string as otherwise some extra chars can sneak in.
    for (int i = strlen(file_path); i < MAX_FILE_PATH_LEN; i++) {
      file_path[i] = '\0';
    }

    Address_t random_peer;
    memcpy(&random_peer, get_random_peer(), sizeof(Address_t));
    // +1 to include terminator
    send_message(random_peer, COMMAND_RETREIVE, file_path,
                 strlen(file_path) + 1);
  }
  // You should never see this printed in your finished implementation
  printf("Client thread done\n");

  return NULL;
}
void send_reply(uint32_t connfd, uint32_t status, char *response_body,
                int responseBodyLength) {
  printf("data to be sent: %d\n", responseBodyLength);
  int maxBlockSize = (MAX_MSG_LEN - REPLY_HEADER_LEN);
  int blockCount =
      fmax(ceil((double)responseBodyLength / (double)maxBlockSize), 1);

  hashdata_t totalHash;
  get_data_sha(response_body, totalHash, responseBodyLength, SHA256_HASH_SIZE);
  printf("block_count is %d\n", blockCount);

  for (int i = 0; i < blockCount; i++) {
    // Construct a reply_header header
    char msg_buf[MAX_MSG_LEN];
    ReplyHeader_t reply_header;
    int replyLength =
        (i < blockCount - 1) ? maxBlockSize : responseBodyLength % maxBlockSize;
    reply_header.length = htonl(replyLength);
    reply_header.status = htonl(status);

    reply_header.this_block = htonl(i);
    reply_header.block_count = htonl(blockCount);

    printf("sending block (%d / %d). Block size is %d.\n", i, blockCount - 1,
           replyLength);

    get_data_sha(response_body + i * maxBlockSize, reply_header.block_hash,
                 replyLength, SHA256_HASH_SIZE);
    memcpy(reply_header.total_hash, &totalHash, SHA256_HASH_SIZE);

    // Copy the header and body together to the message buffer, then write to
    // the socket
    memcpy(msg_buf, &reply_header, REPLY_HEADER_LEN);
    memcpy(msg_buf + REPLY_HEADER_LEN, response_body + i * maxBlockSize,
           replyLength);
    compsys_helper_writen(connfd, msg_buf, REPLY_HEADER_LEN + replyLength);
  }
}

void populate_network_address(Address_t *na, char *ip, uint32_t port,
                              hashdata_t signature) {

  strncpy(na->ip, ip, IP_LEN);
  na->port = port;
  generate_random_salt(na->salt);
  get_signature((char *)signature, SHA256_HASH_SIZE, na->salt, &na->signature);
}

void inform_network(Address_t joiner) {
  for (uint32_t i = 0; i < networkRecord.peer_count; i++) {
    // comparing joiner and my ip + port to avoid sending inform to them
    int joiner_me =
        (memcmp(networkRecord.network[i], my_address, IP_LEN + PORT_LEN) == 0);
    int joiner_themselves =
        (memcmp(networkRecord.network[i], &joiner, IP_LEN + PORT_LEN) == 0);
    if (!joiner_me && !joiner_themselves) {
      // body
      Address_t no_joiner;
      memcpy(&no_joiner, &joiner, sizeof(Address_t));
      no_joiner.port = htonl(no_joiner.port);
      char body[sizeof(Address_t)];
      memcpy(body, &no_joiner, sizeof(Address_t));

      // recipient
      Address_t recipient;
      memcpy(&recipient, networkRecord.network[i], sizeof(Address_t));

      send_message(recipient, COMMAND_INFORM, body, sizeof(Address_t));
    }
  }
}

void handle_register_request(RequestHeader_t rh, int connfd) {
  // Constructing connecting client address:
  Address_t client_address;
  populate_network_address(&client_address, rh.ip, rh.port, rh.signature);

  int response_status = storePeer(&client_address);
  print_network_record();
  if (response_status != STATUS_OK && response_status != STATUS_PEER_EXISTS) {
    return;
  }
  // Writing the body of the buffer
  char responseBodyBuffer[sizeof(Address_t) * networkRecord.peer_count];
  for (uint32_t i = 0; i < networkRecord.peer_count; i++) {
    Address_t network_order_address;
    memcpy(&network_order_address, networkRecord.network[i], sizeof(Address_t));
    network_order_address.port = htonl(network_order_address.port);
    memcpy(responseBodyBuffer + sizeof(Address_t) * i, &network_order_address,
           sizeof(Address_t));
  }
  send_reply(connfd, response_status, responseBodyBuffer,
             sizeof(Address_t) * networkRecord.peer_count);
  if (response_status == STATUS_OK) {
    // inform network of joiner
    inform_network(client_address);
  }
}

/*
 * Handler for all server requests. This will call the relevent function based
 * on the parsed command code
 */

void handle_inform_request(char *body) {
  Address_t joiner;
  memcpy(&joiner, body, sizeof(Address_t));
  joiner.port = ntohl(joiner.port);

  storePeer(&joiner);
  print_network_record();
}

void send_error(int connfd, int status) {
  char msg_buf[MAX_MSG_LEN];

  ReplyHeader_t reply_header;
  reply_header.length = htonl(0);
  reply_header.status = htonl(status);
  reply_header.this_block = htonl(1);
  reply_header.block_count = htonl(1);
  get_data_sha(NULL, reply_header.block_hash, 0, SHA256_HASH_SIZE);
  get_data_sha(NULL, reply_header.total_hash, 0, SHA256_HASH_SIZE);

  memcpy(msg_buf, &reply_header, REPLY_HEADER_LEN);
  compsys_helper_writen(connfd, msg_buf, REPLY_HEADER_LEN);
}

void handle_retreive_request(int connfd, RequestHeader_t request_header,
                             char *body) {

  FILE *fp;
  // Remove leading '/'
  while (body[0] == '/') {
    body = body + 1;
    request_header.length--;
  }
  char fileName[request_header.length + 1];
  memcpy(fileName, body, request_header.length);
  fileName[request_header.length] = '\0';
  printf("file to retreive: %s\n", fileName);

  pthread_mutex_lock(&processingFiles.mutex);
  if (is_file_being_processed(fileName)) {
    printf("could not find file: %s\n", fileName);
    send_error(connfd, STATUS_BAD_REQUEST);
    return;
  }
  pthread_mutex_unlock(&processingFiles.mutex);
  //
  // could use rb mode, however r is best for text files
  // https://stackoverflow.com/questions/2174889/whats-the-differences-between-r-and-rb-in-fopen
  fp = fopen(fileName, "r");
  if (!fp) {
    printf("could not find file: %s\n", fileName);
    send_error(connfd, STATUS_BAD_REQUEST);
    return;
  }
  // find out file size
  if (fseek(fp, 0L, SEEK_END) != 0) {

    printf("issues seeking file: %s", fileName);
    send_error(connfd, STATUS_BAD_REQUEST);
    fclose(fp);
    return;
  }
  int file_size = ftell(fp);
  printf("file size: %d\n", file_size);
  // Go back to start of file
  if (fseek(fp, 0L, SEEK_SET) != 0) {
    printf("issues returning to file start: %s", fileName);
    send_error(connfd, STATUS_BAD_REQUEST);
    fclose(fp);
    return;
  }
  // reading file
  // https://stackoverflow.com/questions/2029103/correct-way-to-read-a-text-file-into-a-buffer-in-c
  // TODO: handle file_size > MAX_MSG_LEN
  char responseBodyBuffer[sizeof(char) * (file_size + 1)];
  size_t newLen = fread(responseBodyBuffer, sizeof(char), file_size, fp);
  if (ferror(fp) != 0) {
    printf("issues reading file: %s\n", fileName);
    send_error(connfd, STATUS_BAD_REQUEST);
    fclose(fp);
  } else {
    responseBodyBuffer[newLen++] = '\0'; /* Just to be safe. */
  }
  fclose(fp);
  // TODO: processingFiles - UNLOCK MUTEX

  // sending reply
  send_reply(connfd, STATUS_OK, responseBodyBuffer,
             sizeof(char) * (file_size + 1));
}

int verify_signature(RequestHeader_t request_header) {
  hashdata_t calculated_hash;
  Address_t hr_peer;
  memcpy(&hr_peer, &request_header.ip, IP_LEN);
  hr_peer.port = request_header.port;

  pthread_mutex_lock(&networkRecord.mutex);
  Address_t *nr_peer = get_peer(&hr_peer);
  if (!nr_peer) {
    printf("could not verify signature: peer %s:%d not in network", hr_peer.ip,
           hr_peer.port);
    return 0;
  }
  Address_t nrcpy_peer;
  memcpy(&nrcpy_peer, nr_peer, sizeof(Address_t));
  pthread_mutex_unlock(&networkRecord.mutex);

  get_signature((char *)request_header.signature, SHA256_HASH_SIZE,
                nrcpy_peer.salt, &calculated_hash);
  if (memcmp(&calculated_hash, &request_header.signature, SHA256_HASH_SIZE) ==
      0) {
    printf("could not verify signature: peer %s:%d has invalid signature",
           hr_peer.ip, hr_peer.port);
    return 0;
  }
  return 1;
}

void *handle_server_request_thread(void *vargp) {
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

  // Validation
  if (request_header.length > MAX_MSG_LEN - REPLY_HEADER_LEN) {
    printf("incomming request length greater than allowed\n");
    send_error(connfd, STATUS_BAD_REQUEST);
    close(connfd);
    return NULL;
  }

  if (is_valid_ip(request_header.ip) != 1) {
    printf("Not a valid IP: %s\n", request_header.ip);
    send_error(connfd, STATUS_BAD_REQUEST);
    close(connfd);
    return NULL;
  }

  if (is_valid_port(request_header.port) != 1) {
    printf("Not a valid port: %d\n", request_header.port);
    send_error(connfd, STATUS_BAD_REQUEST);
    close(connfd);
    return NULL;
  }

  // command is uint
  if (request_header.command > 3 || request_header.command == 0) {
    printf("Not a valid command: %d\n", request_header.command);
    send_error(connfd, STATUS_BAD_REQUEST);
    close(connfd);
    return NULL;
  }

  char requestBodyBuffer[request_header.length];
  compsys_helper_readn(connfd, requestBodyBuffer, request_header.length);

  printf("Received request from %s:%d to run command: %d\n", request_header.ip,
         request_header.port, request_header.command);

  // Reacting to the command
  if (request_header.command == COMMAND_REGISTER) {
    pthread_mutex_lock(&networkRecord.mutex);
    handle_register_request(request_header, connfd);
    pthread_mutex_unlock(&networkRecord.mutex);
  }

  // Verify user signature
  if (!verify_signature(request_header)) {
    close(connfd);
    return NULL;
  }

  if (request_header.command == COMMAND_INFORM) {
    if (request_header.length != PEER_ADDR_LEN) {
      printf("recieved inform request with bad length: %d\n",
             request_header.length);
      return NULL;
    }
    pthread_mutex_lock(&networkRecord.mutex);
    handle_inform_request(requestBodyBuffer);
    pthread_mutex_unlock(&networkRecord.mutex);
  }

  if (request_header.command == COMMAND_RETREIVE) {
    handle_retreive_request(connfd, request_header, requestBodyBuffer);
  }

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
  close(listenfd);

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
  printf("user salt: %.*s \nuser signature: %.*s\n", SALT_LEN, my_address->salt,
         SHA256_HASH_SIZE, my_address->signature);
  // todo: maybe error handle if this fails? if it fails, it's likely because of
  // the malloc failing inside get_signature

  // Start our record of the by adding an empty spot for the address. Make sure
  // any time we update this array we also update the peer_count.
  networkRecord.network = malloc(sizeof(Address_t *));
  networkRecord.peer_count = 0;
  networkRecord.max_size = 1;
  pthread_mutex_t nr_mutex = PTHREAD_MUTEX_INITIALIZER;
  networkRecord.mutex = nr_mutex;

  // Setting up struct to track files being processed
  processingFiles.file_names = malloc(sizeof(char *));
  processingFiles.max_size = 1;
  processingFiles.current_size = 0;
  pthread_mutex_t pf_mutex = PTHREAD_MUTEX_INITIALIZER;
  processingFiles.mutex = pf_mutex;

  // Setup the client and server threads
  pthread_t client_thread_id;
  pthread_t server_thread_id;
  pthread_create(&server_thread_id, NULL, server_thread, NULL);
  printf("Starting to listen on %s:%d\n", my_address->ip, my_address->port);
  pthread_create(&client_thread_id, NULL, client_thread, NULL);

  // Wait for them to complete.
  pthread_join(client_thread_id, NULL);
  pthread_join(server_thread_id, NULL);

  // free mallocs (we never reach this point, but it can't hurt)
  for (uint i = 0; i < networkRecord.peer_count; i++) {
    free(networkRecord.network[i]);
  }
  free(networkRecord.network);

  for (uint i = 0; i < processingFiles.current_size; i++) {
    free(processingFiles.file_names[i]);
  }
  free(processingFiles.file_names);

  free(my_address);

  exit(EXIT_SUCCESS);
}
