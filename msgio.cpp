
#include "msgio.h"
#include <string.h>
int setNonBlocking(int sock)
{
	int flags = 0;
	
	flags = fcntl(sock, F_GETFL, 0);
	flags |= O_NONBLOCK;
	fcntl(sock, F_SETFL, flags);
	
	return 1;
}

static void make_recvipv4addr(struct sockaddr_in *addr, int localport)
{
	memset(addr, 0, sizeof(struct sockaddr_in));
	addr -> sin_family = AF_INET;
	addr -> sin_port   = htons(localport);

	addr -> sin_addr.s_addr = INADDR_ANY;
}

int setupRecv()
{
	int  optval = 1;
	int socklsn = 0;
	struct sockaddr_in serveraddr;



	make_recvipv4addr(&serveraddr, DEFAULT_PORT);


	socklsn = socket(AF_INET, SOCK_STREAM, 0);

	setsockopt( socklsn, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));


	bind(socklsn, (struct sockaddr *)&serveraddr, sizeof(serveraddr));

	return socklsn;
}

int recvPacket(int fd, char *buf,uint32_t sz)
{
	char packet[MSGIO_BUFFER_SZ] = { 0 };
	char * packetPtr = packet;

	int nBytesNeed = sz;
	int nBytesRecv = 0;

	while( nBytesNeed > 0 )
	{
again:		
		nBytesRecv  = read(fd, packetPtr, nBytesNeed);

		if(nBytesRecv == -1){
			if(errno == EINTR) goto again;
			else if(errno == EAGAIN)break;
			perror("read");
			return 0;
		}
		if(nBytesRecv == 0)break;

		nBytesNeed -= nBytesRecv;
		packetPtr  += nBytesRecv;
	}

	strcpy(buf, packet);

	return packetPtr - packet;
}

int sendPacket(int fd, char *buf,uint32_t ssz)
{
       
        char * packetPtr = buf;

        int nBytesNeed = ssz;
        int nBytesSend = 0;

        while( nBytesNeed > 0 )
        {
again:
                nBytesSend  = write(fd, packetPtr, nBytesNeed);

                if(nBytesSend == -1){
                        if(errno == EINTR) goto again;
                        else if(errno == EAGAIN)break;
                        perror("read");
                        return 0;
                }
                if(nBytesSend == 0)break;

                nBytesNeed -= nBytesSend;
                packetPtr  += nBytesSend;
        }

        

        return 1;
}

int getNewConnection(int epollfd, int socklsn)
{
	struct epoll_event 		event;
	struct sockaddr_in 		clientaddr;
	socklen_t 				clientaddrLen;
	int 					sockrcv;

	clientaddrLen = (socklen_t)sizeof(clientaddr);

	sockrcv = accept(socklsn, (struct sockaddr *)&clientaddr, &clientaddrLen);


	setNonBlocking (sockrcv);


	event . data.fd = sockrcv;
  	event . events  = EPOLLIN;

	epoll_ctl (epollfd, EPOLL_CTL_ADD, sockrcv, &event);
	return sockrcv;
}

void getipAddr(char ipbuf[], int fd)
{

	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);

	//printf("%d", getpeername(fd, (struct sockaddr*)&addr, &len));

	struct sockaddr_in *in = (struct sockaddr_in *)&addr;
	inet_ntop(AF_INET, &in->sin_addr, ipbuf, IP_BUFFER_SZ);

	//fprintf(stderr, "%s\n", ipbuf);
}

void setEpoll(int *socklsn, int *epollfd)
{
	struct epoll_event event;

	int templsn = 0;
	int tempfd = 0;
	
	templsn = setupRecv(); 			// create & bind socket


	setNonBlocking ( templsn );	// fcntl
	listen(templsn, MAXCONNEC);	// listen


	tempfd = epoll_create1(0);

	event . data.fd = ( templsn );
	event . events  = EPOLLIN | EPOLLOUT;

	epoll_ctl(tempfd, EPOLL_CTL_ADD, templsn, &event);

	*socklsn = templsn;
	*epollfd = tempfd;
}

