#ifndef __CLIENT__
#define __CLIENT__


#include <string.h>
#include <sgx_dh.h>
#define MAX_CLIENTS 100

typedef enum{
	CLOSE,
	CONNECT,
	WAITINGMSG1,
	WAITINGMSG3,
	WAITINGDATA,
	SUCCESS
}ClientStatus;

typedef struct{
	int num;
}ClientData;

typedef struct{
	int sockfd;
	ClientStatus status;
	ClientData data;
	sgx_ec256_public_t ga;
	sgx_ec256_public_t gb;
	sgx_ec256_private_t prikey;
	uint8_t kdk[16];
	uint8_t sk[16];
}ClientInfo;

typedef struct _client_dh_msg2_t{
	sgx_ec256_public_t ga;
	sgx_ec256_signature_t sig;
	uint8_t hash[32];
}client_dh_msg2_t;

typedef struct _client_dh_msg3_t{
        sgx_ec256_public_t gb;
        uint8_t cmac[SGX_DH_MAC_SIZE];
}client_dh_msg3_t;


ClientInfo clients[MAX_CLIENTS];

uint32_t total_num;
uint32_t cur_success_num;




#endif
