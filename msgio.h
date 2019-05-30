/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/

#ifndef __MSGIO_H
#define __MSGIO_H



#include <sgx_urts.h>
#include <stdio.h>
#include <string>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <unistd.h>
using namespace std;

#define STRUCT_INCLUDES_PSIZE	0
#define STRUCT_OMITS_PSIZE		1

/* A 1MB buffer should be sufficient for demo purposes */
#define MSGIO_BUFFER_SZ	1024*1024
#define IP_BUFFER_SZ 128

#define DEFAULT_PORT	7777		// A C string for getaddrinfo()
#define MAXEVENTS 100
#define MAXCONNEC 10


#ifdef __cplusplus
extern "C" {
#endif

extern char debug;
extern char verbose;

int setNonBlocking(int sock);

static void make_recvipv4addr(struct sockaddr_in *addr, int localport);

int setupRecv();

int recvPacket(int epollfd, char *buf ,uint32_t sz);
int sendPacket(int fd, char *buf,uint32_t ssz);

void setEpoll(int *socklsn, int *epollfd);

int getNewConnection(int epollfd, int socklsn);

void getipAddr(char ipbuf[], int fd);

void setEpoll(int *socklsn, int *epollfd);


//int handleNewConnection(int socklsn, int epollfd);

//int read_msg(int fd,int epollfd,void **dest, size_t *sz);

//void send_msg_partial(void *buf, size_t f_size);
//void send_msg(int fd,int epollfd,void *buf, size_t f_size);

//void fsend_msg_partial(FILE *fp, void *buf, size_t f_size);
//void fsend_msg(FILE *fp, void *buf, size_t f_size);

#ifdef __cplusplus
};
#endif


#endif
