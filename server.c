#include <stdio.h> //Declarations used in most input and output operations;
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <math.h>

#include <sys/types.h> //Defines a number of data types used in system calls
#include <sys/socket.h> //Defines a number of structures needed for sockets;
#include <netinet/in.h> //Contains constants and structures needed for Internet domain addresses. 
#include <unistd.h>
#include <sys/time.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


static const char EXIT_MSG[] = "End Session";
static const char ACK_MSG[] = "I got your message";


static const unsigned char shared_key[] = { // 256 bits
    0x23, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65,
    0x20, 0x3c, 0x73, 0x74, 0x64, 0x69, 0x6f, 0x2e,
    0x68, 0x3e, 0x0d, 0x0a, 0x23, 0x69, 0x6e, 0x63,
    0x6c, 0x75, 0x64, 0x65, 0x20, 0x3c, 0x73, 0x74
};

static const unsigned char iv[] = { // 128 bits
    0x20, 0x20, 0x20, 0x20, 0x20, 0x66, 0x67, 0x65,
    0x74, 0x73, 0x28, 0x62, 0x75, 0x66, 0x66, 0x65
};


static char* now() {
    static char buffer[32];
    
    int millisec;
    struct tm* tm_info;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);

    millisec = lrint(tv.tv_usec/1000.0);
    if (millisec>=1000) {
        millisec -=1000;
        tv.tv_sec++;
    }

    size_t p = strftime(buffer, 26, "%H:%M:%S", tm_info);
    sprintf(buffer+p, ".%03d", millisec);

    return buffer;
}


void error(char *msg) // Displays an error message on stderr and then aborts the program
{
    fprintf(stderr, "%s - %s%s\n", now(), msg, strerror(errno));
    exit(1);
}


void printx(const unsigned char msg[], size_t len) {
    for (size_t i = 0; i < len; ++i)
        printf("%02x ", msg[i]);
}


ssize_t write_all(int fd, const unsigned char msg[], ssize_t msg_len) {
    ssize_t sent = 0;
    ssize_t n;
    while ((n = write(fd, msg+sent, msg_len-sent)) > 0) {  //Write buffer into socket. Returns number of characters written
        sent += n;
    }

    printf("%s - Sent %zu bytes\n", now(), sent);
    return sent;
}

bool encrypt_message(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outlen, unsigned char* in, int inlen) {
    int len;
    if (!EVP_EncryptInit(ctx, EVP_aes_256_cbc(), shared_key, iv))
        return false;
    if (!EVP_EncryptUpdate(ctx, out, outlen, in, inlen))
        return false;
    if (!EVP_EncryptFinal(ctx, out + *outlen, &len))
        return false;
    *outlen += len;
    
    return true;
}

bool decrypt_message(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outlen, unsigned char* in, int inlen) {
    int len;
    if (!EVP_DecryptInit(ctx, EVP_aes_256_cbc(), shared_key, iv))
        return false;
    if (!EVP_DecryptUpdate(ctx, out, outlen, in, inlen))
        return false;
    if (!EVP_DecryptFinal(ctx, out + *outlen, &len))
        return false;
    *outlen += len;

    return true;
}


int main(int argc, char *argv[])
{
    char openssl_err[256];
    int sockfd, newsockfd, portno;
    socklen_t clilen;
    /*sockfd and newsockfd, are array subscripts into the file descriptor table. They store the values returned by the socket system call and the accept system call.portno stores the port number on which the server accepts connections.
    clilen stores the size of the address of the client, which is needed for the
    accept system call.
    */
    char buffer[256]; //The server reads characters from the socket connection into the buffer char.
    struct sockaddr_in serv_addr, cli_addr; //client and server address structures, using the sockaddr_ in Internet address structure. This structure is defined in netinet/in.h.
    ssize_t n; //The number of characters read or written by the read() and write() calls
    
    if (argc < 2) { //check that the user has provided a port number argument and displays an error message
        fprintf(stderr,"ERROR, no port provided\n");
        exit(1);
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0); //Create new streaming IPV4 socket. 0 indicates default protocol, which is TCP. Returns file descriptor table entry
    if (sockfd < 0) //Checks for errors in the creation of the socket. A negative file descriptor table usually indicates an error.
        error("ERROR opening socket");
    bzero((char *) &serv_addr, sizeof(serv_addr)); //Set all values in a buffer to zero, bzero(buf_addr,buf_size)
    portno = atoi(argv[1]); //Retrieves the port no provided as a string and converts it to an integer
    serv_addr.sin_family = AF_INET; //Assign values to the variable serv_addr, which is a structure of type struct sockaddr_in
    serv_addr.sin_port = htons(portno); //Converts a port number in host byte order to a port number in network byte order.
    serv_addr.sin_addr.s_addr = INADDR_ANY; //IPv4 address of the server, which is obtained from the symbolic constant INADDR_ANY.
    if (bind(sockfd, (struct sockaddr *) &serv_addr, //Bind operation and error checking. Second parameter is cast into right type
                sizeof(serv_addr)) < 0) 
                error("ERROR on binding");
    listen(sockfd,5); //Socket listens for new connections. 2nd argument is the number of connections that can be waiting while the process is handling a particular connection 
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen); //Causes the process to block until a new client request comes in
    if (newsockfd < 0)  error("ERROR on accept");


    // init Decrypt / Encrypt
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        error(ERR_error_string(ERR_get_error(), openssl_err));
    
    unsigned char enc_buffer[257], dec_buffer[257];
    int enc_len, dec_len;

    while (1) {
        bzero(buffer,256); //Initialize buffer
        
        if ( (n = read(newsockfd, buffer, 255)) < 0) {
            fprintf(stderr, "%s - ERROR reading from socket:%s\n", now(), strerror(errno)); //Check for errors while reading
            break;
        } else if (n == 0) {
            printf("%s - Connection closed from client side.\n", now());
            break;
        }
        *(buffer + n) = '\0';

        printf("%s - Received: ", now());
        printx((const unsigned char*)buffer, n); //Print message to stdout
        putchar('\n');

        // decrypt the cipher
        if (!decrypt_message(ctx, dec_buffer, &dec_len, (unsigned char*)buffer, n))
            error(ERR_error_string(ERR_get_error(), openssl_err));
        *(dec_buffer + dec_len) = '\0';

        printf("%s - Decrypted message in hex: ", now());
        printx(dec_buffer, dec_len);
        putchar('\n');
        printf("%s - Decrypted message in ascii: %s\n", now(), dec_buffer);

        // Encrypt the response
        strcpy(buffer, ACK_MSG);
        if (!encrypt_message(ctx, enc_buffer, &enc_len, (unsigned char*)buffer, strlen(buffer)))
            error(ERR_error_string(ERR_get_error(), openssl_err));
        *(enc_buffer + enc_len) = '\0';
        
        // Send the response
        if ((n = write_all(newsockfd, enc_buffer, enc_len)) < 0) {
            char buf[256];
            sprintf(buf, "%s - ERROR writing to socket", now());
            perror(buf);
            break;
        } else if (n == 0) {
            printf("%s - Connection closed from client side.\n", now());
            break;
        }

        
        if (strcmp((const char*)dec_buffer, EXIT_MSG) == 0) {
            printf("%s - Exiting...\n", now());
            break;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    close(newsockfd);
    close(sockfd);

    return 0; //Terminates
}