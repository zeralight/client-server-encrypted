#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <math.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> //Defines the structure hostent
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
    for (ssize_t i = 0; i < len; ++i)
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


ssize_t read_all(int fd, unsigned char buffer[], ssize_t msg_len) {
    ssize_t received = 0;
    ssize_t n;
    while ((n = read(fd, buffer+received, msg_len-received)) > 0) {
        received += n;
    }
    
    printf("%s - Received %zu bytes\n", now(), received);
    return received;
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
    int sockfd, portno;
    struct sockaddr_in serv_addr; //The address of the server that client wants to connect to
    struct hostent *server; //Defines the variable server as a pointer to a structure of type hostent
    char buffer[256];
    char openssl_err[256];
    
    if (argc < 3) {
        fprintf(stderr,"usage %s hostname port\n", argv[0]);
        exit(0);
    }
    portno = atoi(argv[2]);
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");
    server = gethostbyname(argv[1]); //Client attempts to get the hostent structure for the server
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }

    bzero((char *) &serv_addr, sizeof(serv_addr)); //Initialize serv_addr
    serv_addr.sin_family = AF_INET; //Set the fields in serv_addr
    bcopy((char *)server->h_addr, //void bcopy(char *s1, char *s2, int length). server->h_addr is a character string, 
        (char *)&serv_addr.sin_addr.s_addr,
        server->h_length);
    serv_addr.sin_port = htons(portno);
    
    if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) //Connect to server. function returns 0 on success and −1 on failure
        error("ERROR connecting");


    // Encryption/Decryption initialization
    EVP_CIPHER_CTX* ctx;
    if (!(ctx = EVP_CIPHER_CTX_new()))
        error(ERR_error_string(ERR_get_error(), openssl_err));
    
    
    unsigned char enc_buffer[257], dec_buffer[257];
    int enc_len, dec_len;
    // main loop
    while (1) {
        printf("Please enter the message: "); //Prompt user for message after connection is successful
        bzero(buffer,256); //Initialize buffer
        fgets(buffer,255,stdin); //Read from stdin into buffer
        *strchr(buffer, '\n') = '\0'; // remove trailing 0x0a
        bool should_quit = !strcmp(buffer, EXIT_MSG); // will end communication after receiving ACK

        // Encrypt the message
        if (!encrypt_message(ctx, enc_buffer, &enc_len, (unsigned char*)buffer, strlen(buffer)))
            error(ERR_error_string(ERR_get_error(), openssl_err));
        *(enc_buffer + enc_len) = '\0';

        // Send the encrypted message
        ssize_t n;
        if ((n = write_all(sockfd, enc_buffer, enc_len)) < 0) {
            fprintf(stderr, "%s - ERROR writing to socket: %s\n", now(), strerror(errno));
            break;
        } else if (n == 0) {
            printf("%s - Lost connection to server.\n", now());
            break;
        }

        // Read Encrypted "ACK"
        if ( (n = read_all(sockfd, (unsigned char*)buffer, 32)) < 0) { // plain ACk is 19 bytes => aes256 encryption will be 32.
            fprintf(stderr, "%s - ERROR reading from socket: %s\n", now(), strerror(errno));
            break;
        } else if (n == 0) {
            printf("%s - Lost connection to server.\n", now());
            break;
        }
        *(buffer + n) = '\0';

        printf("%s - Received: ", now());
        printx((const unsigned char*)buffer, n); //Print message to stdout
        putchar('\n');

        // Decrypt it
        if (!decrypt_message(ctx, dec_buffer, &dec_len, (unsigned char*)buffer, n))
            error(ERR_error_string(ERR_get_error(), openssl_err));
        *(dec_buffer + dec_len) = '\0';

        printf("%s - Decrypted message in hex: ", now());
        printx(dec_buffer, dec_len);
        putchar('\n');
        printf("%s - Decrypted message in ascii: %s\n", now(), dec_buffer);
        if (strcmp((const char*)dec_buffer, ACK_MSG)) {
            fprintf(stderr, "%s - Bad response from Server. Expected %s.\n", now(), ACK_MSG);
            break;
        }

        if (should_quit) {
            printf("%s - Exiting...\n", now());
            break;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    close(sockfd);
        
    return 0; //Exit
}