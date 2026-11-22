
#pragma once
#include "common.h"
#include "sha256.h"
#include <pthread.h>
#include <stdint.h>

// container for file paths
typedef struct FilePath {
  char path[PATH_LEN];
} FilePath_t;

// container for assembling request message headers
typedef struct RequestHeader {
  char ip[IP_LEN];
  uint32_t port;
  hashdata_t signature;
  uint32_t command;
  uint32_t length;
} RequestHeader_t;

// container for assembling reply message headers
typedef struct ReplyHeader {
  uint32_t length;
  uint32_t status;
  uint32_t this_block;
  uint32_t block_count;
  hashdata_t block_hash;
  hashdata_t total_hash;
} ReplyHeader_t;

// container for storing addresses and security information.
// Can be used for both user addresses, and network addresses
typedef struct Address {
  char ip[IP_LEN];
  uint32_t port;
  hashdata_t signature;
  char salt[SALT_LEN];
} Address_t;

typedef struct NetworkRecord {
  Address_t **network;
  uint32_t max_size;
  uint32_t peer_count;
  pthread_mutex_t mutex;
} NetworkRecord_t;

typedef struct ProcessingFiles {
  char **file_names;
  pthread_mutex_t mutex;
  uint32_t current_size;
  uint32_t max_size;
} ProcessingFiles_t;
