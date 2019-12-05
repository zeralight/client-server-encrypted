# Encrypted client/server communication with a shared key.
This program desmonstrates how to use the network/openssl library under linux to build an encrypted client/server communication with a secret pre-shared key.

# Building and Running steps
## Build the server
`gcc server.c -o server -lcrypto -lssl -lm`
`./server listening-port-number`

## Build the client
`gcc client.c -o client -lcrypto -lssl -lm`
`./client server-address server-port`
