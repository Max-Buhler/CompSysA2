## Session Log

20.11.26 - Max:

- Added this Log
- Revised some comments from handout
- Fixed a bug in get_signature: get_data_sha-call
- variable name change sentBlockHash -> receivedBlockHash
- created storePeer function
- created network_record struct, which includes a mutex
- created print_network_record function

21.11.26 - Max:

- refactored Step 3 to statically allocated the entire Response header
- completed Step 4 + 5, we can now print requesting clients

## Memory Allocations

- network[] + every address in network[]
- new_network
- connfd when accepting clients
