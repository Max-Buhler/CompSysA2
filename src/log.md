## Session Log

20.11.26 - Max:

- Added this Log
- Revised some comments from handout
- Fixed a bug in get_signature: get_data_sha-call
- variable name change sentBlockHash -> receivedBlockHash
- created storePeer function
- created network_record struct, which includes a mutex

## Memory Allocations

- network[] + every address in network[]
- new_network
- responseBodyBuffer
