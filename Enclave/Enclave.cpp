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

#ifndef _WIN32
#include "../config.h"
#endif
#include "Enclave_t.h"
#include <string.h>
#include <sgx_utils.h>
#include <sgx_tae_service.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>
#include <string.h>
#include <sgx_tcrypto.h>

sgx_ec256_public_t  g_service_public_key;
sgx_ec256_private_t  g_service_private_key;

#define PSE_RETRIES	5	/* Arbitrary. Not too long, not too short. */

/*----------------------------------------------------------------------
 * WARNING
 *----------------------------------------------------------------------
 *
 * End developers should not normally be calling these functions
 * directly when doing remote attestation:
 *
 *    sgx_get_ps_sec_prop()
 *    sgx_get_quote()
 *    sgx_get_quote_size()
 *    sgx_get_report()
 *    sgx_init_quote()
 *
 * These functions short-circuits the RA process in order
 * to generate an enclave quote directly!
 *
 * The high-level functions provided for remote attestation take
 * care of the low-level details of quote generation for you:
 *
 *   sgx_ra_init()
 *   sgx_ra_get_msg1
 *   sgx_ra_proc_msg2
 *
 *----------------------------------------------------------------------
 */

/*
 * This doesn't really need to be a C++ source file, but a bug in 
 * 2.1.3 and earlier implementations of the SGX SDK left a stray
 * C++ symbol in libsgx_tkey_exchange.so so it won't link without
 * a C++ compiler. Just making the source C++ was the easiest way
 * to deal with that.
 */

sgx_status_t get_report(sgx_report_t *report, sgx_target_info_t *target_info)
{
	sgx_report_data_t report_data;
	memcpy(&report_data, &g_service_public_key,sizeof(sgx_ec256_public_t));
#ifdef SGX_HW_SIM
	return sgx_create_report(NULL, &report_data, report);
#else
	return sgx_create_report(target_info, &report_data, report);
#endif
}
sgx_status_t enclave_get_ps_sec_prop(sgx_ps_sec_prop_desc_t* security_property)
{

	sgx_ps_sec_prop_desc_t ps_sec_prop_desc;
	
	sgx_status_t status= SGX_ERROR_SERVICE_UNAVAILABLE;
	int retries= PSE_RETRIES;

	do {
		status= sgx_create_pse_session();
		if ( status != SGX_SUCCESS ) return status;
	} while (status == SGX_ERROR_BUSY && retries--);
	if ( status != SGX_SUCCESS ) return status;

	status= sgx_get_ps_sec_prop(&ps_sec_prop_desc);
	
	if ( status != SGX_SUCCESS ) return status;
	//*security_property = ps_sec_prop_desc;
	memcpy(security_property,&ps_sec_prop_desc,sizeof(ps_sec_prop_desc));
	sgx_close_pse_session();
	return status;
}

size_t get_pse_manifest_size ()
{
	return sizeof(sgx_ps_sec_prop_desc_t);
}

sgx_status_t get_pse_manifest(char *buf, size_t sz)
{
	sgx_ps_sec_prop_desc_t ps_sec_prop_desc;
	sgx_status_t status= SGX_ERROR_SERVICE_UNAVAILABLE;
	int retries= PSE_RETRIES;

	do {
		status= sgx_create_pse_session();
		if ( status != SGX_SUCCESS ) return status;
	} while (status == SGX_ERROR_BUSY && retries--);
	if ( status != SGX_SUCCESS ) return status;

	status= sgx_get_ps_sec_prop(&ps_sec_prop_desc);
	if ( status != SGX_SUCCESS ) return status;

	memcpy(buf, &ps_sec_prop_desc, sizeof(ps_sec_prop_desc));

	sgx_close_pse_session();

	return status;
}



void enclave_add_client(int *fd){

	int i;
	for(i=0;i<MAX_CLIENTS;i++){
		if(clients[i].status == CLOSE){
			clients[i].sockfd = *fd;
			clients[i].status = CONNECT;
		}
	
	}

}


void enclave_initalize(sgx_ec256_public_t *cpubkey,sgx_ec256_private_t *cprikey){
	memset(clients,0,sizeof(ClientInfo) * MAX_CLIENTS);
	cur_success_num = 0;	
	sgx_ecc_state_handle_t ecc_state_handle;
	sgx_status_t status;
	status = sgx_ecc256_open_context( &ecc_state_handle );
	if(status != SGX_SUCCESS)
		return;
	status = sgx_ecc256_create_key_pair(&g_service_private_key,&g_service_public_key,ecc_state_handle);
	if(status != SGX_SUCCESS)
                return;

	status = sgx_ecc256_close_context( ecc_state_handle );
        if(status != SGX_SUCCESS)
                return;
	*cpubkey = g_service_public_key;
	*cprikey = g_service_private_key;
	total_num = 1;
	cur_success_num = 0;
}

void enclave_get_client_status(int* fd,ClientStatus *cstatus){
	int i;
	for(i=0;i<MAX_CLIENTS;i++){
		if(clients[i].sockfd == *fd)
			*cstatus = clients[i].status;
	}
	
}

void enclave_set_client_status(int *fd,ClientStatus *cstatus){
	int i;
        for(i=0;i<MAX_CLIENTS;i++){
                if(clients[i].sockfd == *fd)
                        clients[i].status = *cstatus;
        }
       
}

void enclave_generate_msg2(int *fd,client_dh_msg2_t *msg2,uint8_t *res){
	int i;
	sgx_ecc_state_handle_t ecc_state_handle;
        sgx_status_t status;
	sgx_ec256_signature_t temp_sig;
	uint32_t sz = sizeof(sgx_ec256_public_t);
//	sgx_sha256_hash_t hash;
	


        for(i=0;i<MAX_CLIENTS;i++){
                if(clients[i].sockfd == *fd){
			
			status = sgx_ecc256_open_context( &ecc_state_handle );
        		if(status != SGX_SUCCESS)
                		goto error_client;
        		status = sgx_ecc256_create_key_pair(&clients[i].prikey,&clients[i].ga,ecc_state_handle);
        		if(status != SGX_SUCCESS)
                		goto error_client;

        		status = sgx_ecc256_close_context( ecc_state_handle );
        		if(status != SGX_SUCCESS)
				goto error_client;
/*
			status = sgx_sha256_msg((uint8_t*)&clients[i].ga,sz,&hash);
			if(status != SGX_SUCCESS)
                                goto error_client;
*/


			status = sgx_ecc256_open_context( &ecc_state_handle );
                        if(status != SGX_SUCCESS)
                               goto error_client;
			uint8_t temp[64];	
                        status = sgx_ecdsa_sign((uint8_t *)&clients[i].ga,sz,&g_service_private_key,&temp_sig,ecc_state_handle);
                        if(status != SGX_SUCCESS)
                                goto error_client;
			
		//	sgx_ecdsa_verify((uint8_t*)&hash,32,&g_service_public_key,&temp_sig,res,ecc_state_handle);
                        status = sgx_ecc256_close_context( ecc_state_handle );
                        if(status != SGX_SUCCESS)
                                goto error_client;


			clients[i].status = WAITINGMSG3;

			
			memcpy(msg2->ga.gx,clients[i].ga.gx,32);
			memcpy(msg2->ga.gy,clients[i].ga.gy,32);
			memcpy(msg2->sig.x,temp_sig.x,32);

			memcpy(msg2->sig.y,temp_sig.y,32);
			uint8_t hash[64]={0};
			memcpy(msg2->hash,&hash,32);
			status = sgx_ecc256_open_context( &ecc_state_handle );
			sgx_ecdsa_verify((uint8_t *)&msg2->ga,sz,&g_service_public_key,&msg2->sig,res,ecc_state_handle);
			status = sgx_ecc256_close_context( ecc_state_handle );

		}
        }

error_client:
	
       return; 
}

void enclave_process_msg3(int *fd,client_dh_msg3_t *msg3,uint8_t *res){
	int i;
        sgx_ecc_state_handle_t ecc_state_handle;
        sgx_status_t status;
	sgx_ec256_dh_shared_t sk;
	sgx_cmac_128bit_key_t cmackey;
	sgx_cmac_state_handle_t cmac_handle;
	uint8_t cmacans[SGX_DH_MAC_SIZE];
	*res = 0;
	int j;
	for(i=0;i<MAX_CLIENTS;i++){
		if(clients[i].sockfd == *fd){
			status = sgx_ecc256_open_context( &ecc_state_handle );
                        if(status != SGX_SUCCESS)
				return ;
			status = sgx_ecc256_compute_shared_dhkey(&clients[i].prikey,&msg3->gb,&sk,ecc_state_handle);

			if(status != SGX_SUCCESS)
                                return ;
			status = sgx_ecc256_close_context( ecc_state_handle );
                        if(status != SGX_SUCCESS)
                                return ;
			memset(&cmackey,0,sizeof(sgx_cmac_128bit_key_t));
			sgx_cmac128_init(&cmackey,&cmac_handle);
			sgx_cmac128_update((uint8_t*)&sk,32,cmac_handle);
			sgx_cmac128_final(cmac_handle,(sgx_cmac_128bit_tag_t*)clients[i].kdk);
				
			memcpy(&cmackey,clients[i].kdk,16);
			sgx_cmac128_init(&cmackey,&cmac_handle);
                        sgx_cmac128_update((unsigned char *)("\x01SMK\x00\x80\x00"),7,cmac_handle);
                        sgx_cmac128_final(cmac_handle,(sgx_cmac_128bit_tag_t*)clients[i].sk);
			
		
			memcpy(&cmackey,clients[i].sk,16);
                        sgx_cmac128_init(&cmackey,&cmac_handle);
                        sgx_cmac128_update((unsigned char *)&msg3->gb,sizeof(sgx_ec256_public_t),cmac_handle);
                        sgx_cmac128_final(cmac_handle,(sgx_cmac_128bit_tag_t*)cmacans);
			for(j=0;j<16;j++)
				if(cmacans[j] != msg3->cmac[j])*res = 0;
			

		}
	}
	*res = 1;

}
void enclave_cal_ava(int *ok,int *avg){
	*ok = (cur_success_num == total_num);
	int i;
	if(*ok)
	{
		int sum = 0;
		for(i=0;i<MAX_CLIENTS;i++){
			if(clients[i].status == SUCCESS){
				sum += clients[i].data.num;
			}
		}
		*avg = sum/total_num;
	}
}

void enclave_process_clientdata(int *fd,int *num,uint32_t* shoudwait)
{
	int i;
	for(i=0;i<MAX_CLIENTS;i++){
                if(clients[i].sockfd == *fd){
			clients[i].data.num = *num;
			clients[i].status = SUCCESS;
			cur_success_num += 1;
		}
	}
	*shoudwait =  cur_success_num;
}
