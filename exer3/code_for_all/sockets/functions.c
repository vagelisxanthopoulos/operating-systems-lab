#include <poll.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <fcntl.h>

#include <sys/ioctl.h>
 
#include <sys/types.h>
#include <sys/stat.h>

//#include <crypto/cryptodev.h>
#include "cryptodev.h"
#include "socket-common.h"

ssize_t insist_read(int fd, void *buf, size_t cnt)
{
    ssize_t ret;
    size_t orig_cnt = cnt;

    while (cnt > 0) {
        ret = read(fd, buf, cnt);
        if (ret < 0)
            return ret;

        buf += ret;
        cnt -= ret;
    }

    return orig_cnt;
};

int fill_urandom_buf(unsigned char *buf, size_t cnt)
{
    int crypto_fd;
    int ret = -1;

    crypto_fd = open("/dev/urandom", O_RDONLY);
    if (crypto_fd < 0)
        return crypto_fd;

    ret = insist_read(crypto_fd, buf, cnt);
    close(crypto_fd);

    return ret;
};

ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
	    ret = write(fd, buf, cnt);
	    if (ret < 0)
	        return ret;
			
	    buf += ret;
	    cnt -= ret;
	}

	return orig_cnt;
};


//reads from stdin into buffer until newline and returns how many chars have been written
int get_message_stdin(unsigned char *buffer, int size)
{
	char c;
    ssize_t ret;
	ssize_t last = 0;
	while(c != '\n' && size != 0)  //if we read newline or reach the end of buffer we return
	{
		ret = read(0, &c, 1);
		if (ret < 0)
		{
			perror("read");
			exit(1);
		}
		buffer[last++] = c;  //fill buffer
		size--;  //decrement size to know how many chars we can write
	}
	return last;  
};

void enDeCrypt(int flag, unsigned char* input, unsigned char* output)
{
	int cfd;

	cfd = open("/dev/cryptodev0", O_RDWR);
	if (cfd < 0) {
		perror("open(/dev/cryptodev0)");
		exit(1);
	}

	struct session_op sess;
    struct crypt_op cryp;
    struct {
		unsigned char 	in[DATA_SIZE],
				encrypted[DATA_SIZE],
				decrypted[DATA_SIZE],
				iv[BLOCK_SIZE],
				key[KEY_SIZE];
	} data;

	memset(&sess, 0, sizeof(sess));
    memset(&cryp, 0, sizeof(cryp));
	memset(&data.in, 0, DATA_SIZE);
	memset(&data.encrypted, 0, DATA_SIZE);
	memset(&data.decrypted, 0, DATA_SIZE);

	memcpy(data.iv, (unsigned char *)IV, 16);
	memcpy(data.key, (unsigned char *)KEY, 16);

	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key = data.key;

	if (ioctl(cfd, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		exit(1);
	}

	cryp.ses = sess.ses;
    cryp.iv = data.iv;

    if(flag == 0) //encrypt
    {
        memcpy(data.in, input, DATA_SIZE);
        cryp.len = sizeof(data.in);
        cryp.src = data.in;
	    cryp.dst = data.encrypted;
	    cryp.op = COP_ENCRYPT;

        if (ioctl(cfd, CIOCCRYPT, &cryp)) {
	    	perror("ioctl(CIOCCRYPT)");
	    	exit(1);
	    }

        memcpy(output, data.encrypted, DATA_SIZE);
    }
	else //decrypt
	{
		memcpy(data.encrypted, input, DATA_SIZE);
		cryp.len = sizeof(data.encrypted);
    	cryp.src = data.encrypted;
		cryp.dst = data.decrypted;
		cryp.op = COP_DECRYPT;

    	if (ioctl(cfd, CIOCCRYPT, &cryp)) {
			perror("ioctl(CIOCCRYPT)");
			exit(1);
		}
		memcpy(output, data.decrypted, DATA_SIZE);
	}

	if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
		perror("ioctl(CIOCFSESSION)");
		exit(1);
	}
    close(cfd);
};

void getorsend(int fd, int who)
{
    unsigned char input[DATA_SIZE];
	unsigned char output[DATA_SIZE];

    const int nfds = 2; //we are polling for two fds
	struct pollfd pfds[2]; //we need this to check whether theres is message from stdin or from socket
    pfds[0].fd = 0;
	pfds[0].events = POLLIN;
	pfds[1].fd = fd;
	pfds[1].events = POLLIN;

	char logout[] = "bye\n";  //if we get "bye" we leave
	int message_size, ready;

    while(1)
    {    
        pfds[0].revents = 0; //clear revents
	    pfds[1].revents = 0;
	    memset(input, 0, DATA_SIZE);
		memset(output, 0, DATA_SIZE);

        ready = poll(pfds, nfds, -1); //poll
	    if (ready == -1) 
	    {
		    perror("poll");
		    exit(1);
	    }
        
	    if (pfds[0].revents & POLLIN) //we can read message from stdin
	    {
		    message_size = get_message_stdin(input, DATA_SIZE);

		    enDeCrypt(0, input, output);
		
		    if (insist_write(fd, output, DATA_SIZE) != DATA_SIZE) {
			    perror("write to remote peer failed");
			    return;
		    }
		    if (strncmp(logout, (char *)input, strlen(logout)) == 0) return;  //we compare only first strlen(logout) chars
			
			memset(output, 0, DATA_SIZE);
			memset(input, 0, DATA_SIZE);
	    }

	    if (pfds[1].revents & POLLIN) //we can read message from socket
	    {
		    message_size = insist_read(fd, input, DATA_SIZE);
		    if (message_size < 0) return; //we got eof

		    enDeCrypt(1, input, output);
			
		    if (who == 0) fprintf(stdout, "Client: ");
            else fprintf(stdout, "Server: ");
            fflush(stdout);

		    if (insist_write(1, output, DATA_SIZE) != DATA_SIZE) {
			    perror("write to remote peer failed");
			    return;
		    }
		    if (strncmp(logout, (char *)output, strlen(logout)) == 0) return;  //if we get "bye" we leave
	    }
    } 
};
