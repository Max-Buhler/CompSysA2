## Session Log

20.11.26 - Max:

- Added this Log
- Revised some comments from handout
- Fixed a bug in get_signature: get_data_sha-call, referenced param, instead of
  dereferencing
- variable name change sentBlockHash -> receivedBlockHash
- created storePeer function, also included dynamically allocating the peer
  address
- created network_record struct, which includes a mutex
- created print_network_record function

21.11.26 - Max:

- refactored Step 3 to statically allocated the entire Response header
- completed Step 4 + 5, we can now print requesting clients
- fixed bug in printing function, printing the signature including the salt.
- fixed bug in addressExistsInNetwork: memcmp returns 0 if equal.
- completed Step 6, server now includes registerer in network
- We no longer save our own address in the network array, as it is not the
  network signature.
- Completed Step 7
- Reworked registering, such that registering when client is already in network
  still works.
- fixed bug, where we used network byte ordering to index a memcpy
- Encapsulated memory allocation into the storePeer function
- Completed Step 8 + 9
- Completed Step 10 + 11
- Completed Step 12

## Memory Allocations

- network[] + every address in network[]
- new_network
- connfd when accepting clients

## Open Sockets (Incompet)

-
