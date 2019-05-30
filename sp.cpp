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


using namespace std;


#include "config.h"

# include "Enclave_u.h"


#if !defined(SGX_HW_SIM)&&!defined(_WIN32)
#include "sgx_stub.h"
#endif

#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <sgx_urts.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <getopt.h>
#include <unistd.h>

#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <string>
#include "common.h"
#include "protocol.h"
#include "sgx_detect.h"
#include "hexutil.h"
#include "fileio.h"
#include "base64.h"
#include "crypto.h"
#include "msgio.h"
#include "logfile.h"
#include "quote_size.h"
#include "iasrequest.h"
#include "settings.h"
#include "json.hpp"
#include "Enclave/client.h"
#include "byteorder.h"
#define MAX_LEN 80

using namespace json;

# define _rdrand64_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })


#ifdef __x86_64__
#define DEF_LIB_SEARCHPATH "/lib:/lib64:/usr/lib:/usr/lib64"
#else
#define DEF_LIB_SEARCHPATH "/lib:/usr/lib"
#endif

#define SPID_VALUE "459AFA495880181B0BACAC57F0D1A157"
#define IAS_SIGNING_CAFILE  "IAS/AttestationReportSigningCACert.pem"
#define IAS_CERT_FILE "IAS/client.crt"
#define IAS_CERT_KEY "IAS/client.key" 

typedef struct config_struct {
	
	int flags;	

	sgx_spid_t spid;                       //SPID *

	unsigned int apiver;                   //API version *
	sgx_quote_nonce_t nonce;

	char *proxy_server;
	char *ca_bundle;                      //*
	char *user_agent;
	char *cert_file;//*
	char *cert_key_file;//*
	char *cert_passwd_file;
	unsigned int proxy_port;
	char *cert_type[4];                   //*
	X509_STORE *store;//*
	X509 *signing_ca;//*
	int strict_trust;	
} config_t;


int handleNewConnection(int socklsn,int epollfd);
int handleNewRead(int clientfd,int epollfd,char rcvbuf[],uint32_t sz);
int get_sigrl (IAS_Connection *ias, int version, sgx_epid_group_id_t gid,
        char **sig_rl, uint32_t *sig_rl_size);
int get_attestation_report(IAS_Connection *ias, int version,
	const char *b64quote, const char *b64manifest,
	int strict_trust); 
int file_in_searchpath (const char *file, const char *search, char *fullpath,
	size_t len);

int initializeConfig(config_t &config);

int serverloop(int socklsn,int epollfd);


sgx_status_t sgx_create_enclave_search (
	const char *filename,
	const int edebug,
	sgx_launch_token_t *token,
	int *updated,
	sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr
);
int get_quote(sgx_enclave_id_t eid,config_t *config,IAS_Connection *ias
		,char *& b64quote,char *& b64manifest);
void usage();

char debug= 0;
char verbose= 0;
string fulltext;

sgx_enclave_id_t eid= 0;


#define OPT_PSE		0x01
#define OPT_NONCE	0x02
#define OPT_LINK	0x04
#define OPT_PUBKEY	0x08

/* Macros to set, clear, and get the mode and options */

#define SET_OPT(x,y)	x|=y
#define CLEAR_OPT(x,y)	x=x&~y
#define OPT_ISSET(x,y)	x&y


# define ENCLAVE_NAME "Enclave.signed.so"

sgx_ec256_public_t service_pub_key;

vector<int> fds;
int main (int argc, char *argv[])
{
	config_t config;
	sgx_launch_token_t token= { 0 };
	sgx_status_t status,sgx_rv;
	int updated= 0;
	int sgx_support;
	IAS_Connection *ias= NULL;
	uint32_t i;
	
	

	int epollfd,socklsn;

	verbose=0;

	/* Create a logfile to capture debug output and actual msg data */
	fplog = create_logfile("sp.log");
	dividerWithText(fplog, "sp Log Timestamp");

	const time_t timeT = time(NULL);
	struct tm lt;
	


	localtime_r(&timeT,&lt);

	fprintf(fplog, "%4d-%02d-%02d %02d:%02d:%02d\n", 
		lt.tm_year + 1900, 
		lt.tm_mon + 1, 
		lt.tm_mday,  
		lt.tm_hour, 
		lt.tm_min, 
		lt.tm_sec);
	divider(fplog);

	

	memset(&config,0,sizeof(config));
	SET_OPT(config.flags,OPT_LINK);
//	SET_OPT(config.flags,OPT_PSE);
	strncpy((char *)config.cert_type, "PEM", 3);
	
	config.apiver= IAS_API_DEF_VERSION;


	/* Use the default CA bundle unless one is provided */

	if ( config.ca_bundle == NULL ) {
		config.ca_bundle= strdup(DEFAULT_CA_BUNDLE);
		if ( config.ca_bundle == NULL ) {
			perror("strdup");
			return 1;
		}
		if ( debug ) eprintf("+++ Using default CA bundle %s\n",
			config.ca_bundle);
	}
	
	if (!cert_load_file(&config.signing_ca, IAS_SIGNING_CAFILE)) {
		crypto_perror("cert_load_file");
		eprintf("%s: could not load IAS Signing Cert CA\n", IAS_SIGNING_CAFILE);
		return 1;
	}
	config.store = cert_init_ca(config.signing_ca);
	if (config.store == NULL) {
		eprintf("%s: could not initialize certificate store\n", IAS_SIGNING_CAFILE);
		return 1;
	}
	
	config.cert_file = strdup(IAS_CERT_FILE);
	if (config.cert_file == NULL) {
		perror("strdup");
		return 1;
	}

	config.cert_key_file = strdup(IAS_CERT_KEY);
	if (config.cert_key_file == NULL) {
		perror("strdup");
		return 1;
	}

	if (!from_hexstring((unsigned char *)&config.spid, (unsigned char *)SPID_VALUE, 16)) {
		eprintf("SPID must be 32-byte hex string\n");
		return 1;
	}

	try {
		ias = new IAS_Connection(IAS_SERVER_DEVELOPMENT,0);
	}
	catch (...) {
		eprintf("exception while creating IAS request object\n");
		return 1;
	}
	
	
	ias->client_cert(config.cert_file, (char *)config.cert_type);
	ias->cert_store(config.store);
	if ( strlen(config.ca_bundle) ) ias->ca_bundle(config.ca_bundle);
	ias->client_key(config.cert_key_file, NULL);

	/* Can we run SGX? */

#ifndef SGX_HW_SIM
	sgx_support = get_sgx_support();
	if (sgx_support & SGX_SUPPORT_NO) {
		fprintf(stderr, "This system does not support Intel SGX.\n");
		return 1;
	} else {
		if (sgx_support & SGX_SUPPORT_ENABLE_REQUIRED) {
			fprintf(stderr, "Intel SGX is supported on this system but disabled in the BIOS\n");
			return 1;
		}
		else if (sgx_support & SGX_SUPPORT_REBOOT_REQUIRED) {
			fprintf(stderr, "Intel SGX will be enabled after the next reboot\n");
			return 1;
		}
		else if (!(sgx_support & SGX_SUPPORT_ENABLED)) {
			fprintf(stderr, "Intel SGX is supported on this sytem but not available for use\n");
			fprintf(stderr, "The system may lock BIOS support, or the Platform Software is not available\n");
			return 1;
		}
	} 
#endif

	
//	setEpoll(&socklsn,&epollfd);

//	serverloop(socklsn,epollfd);

	/* Launch the enclave */

	
	status = sgx_create_enclave_search(ENCLAVE_NAME,
		SGX_DEBUG_FLAG, &token, &updated, &eid, 0);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_create_enclave: %s: %08x\n",
			ENCLAVE_NAME, status);
		if ( status == SGX_ERROR_ENCLAVE_FILE_ACCESS ) 
			fprintf(stderr, "Did you forget to set LD_LIBRARY_PATH?\n");
		return 1;
	
	}

	sgx_ec256_private_t service_pri_key;	
	status =  enclave_initalize(eid,&service_pub_key,&service_pri_key);
	if(status != SGX_SUCCESS){
		 fprintf(stderr, "enclave initalize failed\n");
	}
	fprintf(stderr,"\nservice_prikey = ");
        print_hexstring(stderr, service_pri_key.r, 32);
	
        fprintf(stderr,"\nservice_pubkey.gx = ");
        print_hexstring(stderr, service_pub_key.gx, 32);
        fprintf(stderr,"\nservice_pubkey.gy = ");
	print_hexstring(stderr, service_pub_key.gy, 32);

	
	char *b64quote=NULL;
	char *b64manifest=NULL;
	if(get_quote(eid,&config,ias,b64quote,b64manifest)){
		fprintf(stderr,"get quote error\n");
	}

	get_attestation_report(ias,config.apiver,b64quote,b64manifest,config.strict_trust);
	if(b64quote!=NULL)free(b64quote);
	if(b64manifest!=NULL)free(b64manifest);

//	fprintf(stderr,"%s\n",fulltext.c_str());
	

	setEpoll(&socklsn,&epollfd);
	serverloop(socklsn,epollfd);

	close_logfile(fplog);
}

int serverloop(int socklsn,int epollfd)
{
	struct epoll_event events[MAXEVENTS];

	//enclave_clean_list_client
	
	while(1){
		
		int numEvts;
		int i;
		/*int ok,avg;
		enclave_cal_ava(eid,&ok,&avg);
		if(ok){
			fprintf(stderr,"avg = %d\n",avg);
		}*/
		numEvts = epoll_wait(epollfd,events,MAXEVENTS,10);

		for(i = 0; i < numEvts; i++){
			if((events[i].events & EPOLLERR) ||			
         			(events[i].events & EPOLLHUP) ||
       				(!(events[i].events & EPOLLIN)))
			{
				//char ipbuf [MAXBUFLEN];
				//getipAddr(ipbuf, events[i].data.fd);
				//strcat(ipbuf, " error");
				//send( stipc -> sockfd[ 0 ], (void*)&ipbuf, sizeof(ipbuf), 0 );
				close( events[i].data.fd );
				continue;
			}
			else if(socklsn == events[i].data.fd){
				if(handleNewConnection(socklsn,epollfd) == 0)
				{
					fprintf(stderr,"accept error");
					continue;
				}		
			}
			else{
				char rbuf[MSGIO_BUFFER_SZ] = {0};
				handleNewRead(events[i].data.fd,epollfd,rbuf,MSGIO_BUFFER_SZ);
				
			}
		}

	}
}

int handleNewConnection(int socklsn,int epollfd)
{
	char ipbuf[IP_BUFFER_SZ] = {0};
	sgx_status_t status;
	int fd = getNewConnection(epollfd,socklsn);

	if(fd == -1) return 0;

	getipAddr( ipbuf, fd);
	
	fprintf(stdout,"request from %s\n",ipbuf);

	status = enclave_add_client(eid,&fd);
	
	return 1;
}

int handleNewRead(int clientfd,int epollfd,char rcvbuf[],uint32_t sz)
{
	
	uint32_t readsz;
	
	//readsz = read(clientfd,rcvbuf,1024);

	//fprintf(stdout,"%d\n",readsz);
	
	if((readsz = recvPacket(clientfd,rcvbuf,sz)) == 0){   //client close
		struct epoll_event event;
		event.data.fd = clientfd;
		event.events = EPOLLIN;
		fprintf(stdout,"close client\n");
		//enclave_close_fd
		ClientStatus cstatus = CLOSE;
		sgx_status_t status;
		status = enclave_set_client_status(eid,&clientfd,&cstatus);	
			
		epoll_ctl(epollfd,EPOLL_CTL_DEL,clientfd,&event);

		return 0;
	}else{
		ClientStatus cstatus;
		sgx_status_t status;
		status = enclave_get_client_status(eid,&clientfd,&cstatus);
		char sbuf[MSGIO_BUFFER_SZ]={0};
		uint32_t sz;
		uint32_t sz_t;
		switch(cstatus){
		case CONNECT:
			fprintf(stdout,"%s\n",rcvbuf);
			client_dh_msg2_t msg2;
			uint8_t temp[32];
			uint8_t res;
			status = enclave_generate_msg2(eid,&clientfd,&msg2,&res);

			fprintf(stderr,"res = %d\n",res);


		//	reverse_bytes(temp,msg2.sig.x,32);
		//	memcpy(msg2.sig.x,temp,32);

		//	reverse_bytes(temp,msg2.sig.y,32);
		//	memcpy(msg2.sig.y,temp,32);
			fprintf(stderr,"msg2.ga.gx = ");
			print_hexstring(stderr, msg2.ga.gx, 32);	
			fprintf(stderr,"\n msg2.ga.gy = ");

			print_hexstring(stderr, msg2.ga.gy, 32);
			fprintf(stderr,"\n msg2.sig.x = ");

			print_hexstring(stderr, msg2.sig.x, 32);
			fprintf(stderr,"\n msg2.sig.y = ");

                        print_hexstring(stderr, msg2.sig.y, 32);
			fprintf(stderr,"\n msg2.hash = ");
			print_hexstring(stderr, msg2.hash, 32);

			sz = sizeof(client_dh_msg2_t);
			memcpy(sbuf,(void*)&msg2,sz);
			sz_t = fulltext.size();
			memcpy(sbuf+sz,fulltext.c_str(),sz_t);
			sendPacket(clientfd,sbuf,sz+sz_t);
			cstatus = WAITINGMSG3;
	           
        	        status = enclave_set_client_status(eid,&clientfd,&cstatus);
			break;
       
        	case WAITINGMSG3:

			client_dh_msg3_t msg3;
			memcpy(&msg3,rcvbuf,readsz);
			fprintf(stderr,"msg3.gb.gx = ");
                        print_hexstring(stderr, msg3.gb.gx, 32);
                        fprintf(stderr,"\n msg3.gb.gy = ");

                        print_hexstring(stderr, msg3.gb.gy, 32);
                        fprintf(stderr,"\n msg3.cmac = ");

                        print_hexstring(stderr, msg3.cmac, 16);
                        
			uint8_t resans;
			status = enclave_process_msg3(eid,&clientfd,&msg3,&resans);
			if(status != SGX_SUCCESS)
                        {
				 fprintf(stderr,"\n error");

			}
			if(resans)
			{
				fprintf(stderr,"\n success!!!");
                        //print_hexstring(stderr, reskdk, 16);
				memset(sbuf,0,sizeof(sbuf));
				strcpy(sbuf,"Please send you num:");
				sendPacket(clientfd,sbuf,strlen(sbuf));

				cstatus = WAITINGDATA;
                       
                       	 	status = enclave_set_client_status(eid,&clientfd,&cstatus);
			}else  fprintf(stderr,"\n error");

			break;
        	case WAITINGDATA:
			int a;
			memcpy(&a,rcvbuf,4);
			fprintf(stderr,"get num = %d\n",a);
			uint32_t shouldw;
			enclave_process_clientdata(eid,&clientfd,&a,&shouldw);
			 fprintf(stderr,"get ads = %d\n",shouldw);

			sendPacket(clientfd,(char *)&shouldw,4);
			break;
		}

		//strcpy(sbuf,fulltext.c_str());
		
		//sendPacket(clientfd, sbuf,strlen(sbuf));


	}
}
int get_quote(sgx_enclave_id_t eid,config_t *config,IAS_Connection *ias,char *& b64quote ,char*& b64manifest){
	
	

	sgx_status_t status, sgxrv;
	sgx_quote_t *quote;
	sgx_report_t report;
	sgx_report_t qe_report;
	sgx_target_info_t target_info;
	sgx_epid_group_id_t epid_gid;                        //GID	

	char *sigrl = NULL;
	uint32_t sig_rl_size;
	uint32_t sz= 0;
	uint32_t flags= config->flags;
	sgx_quote_sign_type_t linkable= SGX_UNLINKABLE_SIGNATURE;
	sgx_ps_cap_t ps_cap;
	char *pse_manifest = NULL;
	size_t pse_manifest_sz;
	

	if (OPT_ISSET(flags, OPT_LINK)) linkable= SGX_LINKABLE_SIGNATURE;

	/* Platform services info */
	if (OPT_ISSET(flags, OPT_PSE)) {
		status = sgx_get_ps_cap(&ps_cap);
		if (status != SGX_SUCCESS) {
			fprintf(stderr, "sgx_get_ps_cap: %08x\n", status);
			return 1;
		}

		status = get_pse_manifest_size(eid, &pse_manifest_sz);
		if (status != SGX_SUCCESS) {
			fprintf(stderr, "get_pse_manifest_size: %08x\n",
				status);
			return 1;
		}

		pse_manifest = (char *) malloc(pse_manifest_sz);

		status = get_pse_manifest(eid, &sgxrv, pse_manifest, pse_manifest_sz);
		if (status != SGX_SUCCESS) {
			fprintf(stderr, "get_pse_manifest: %08x\n",
				status);
			return 1;
		}
		if (sgxrv != SGX_SUCCESS) {
			fprintf(stderr, "get_sec_prop_desc_ex: %08x\n",
				sgxrv);
			return 1;
		}
	}
	
	
	
	status= sgx_init_quote(&target_info, &epid_gid);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_init_quote: %08x\n", status);
		return 1;
	}
	
	//get sigrl
	if(!get_sigrl(ias, config->apiver, epid_gid, &sigrl, &sig_rl_size)){
		eprintf("could not retrieve the sigrl\n");
		return -1;	
	}	
	
	status= get_report(eid, &sgxrv, &report, &target_info);	
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "get_report: %08x\n", status);
		return 1;
	}
	if ( sgxrv != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_create_report: %08x\n", sgxrv);
		return 1;
	}

	// sgx_get_quote_size() has been deprecated, but our PSW may be too old
	// so use a wrapper function.

	if (! get_quote_size(&status, &sz)) {
		fprintf(stderr, "PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
		return 1;
	}
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "SGX error while getting quote size: %08x\n", status);
		return 1;
	}
	
	quote= (sgx_quote_t *) malloc(sz);
	if ( quote == NULL ) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}
	memset(quote, 0, sz);
	status= sgx_get_quote(&report, linkable, &config->spid,
		(OPT_ISSET(flags, OPT_NONCE)) ? &config->nonce : NULL,
		sig_rl_size?(uint8_t*)(sigrl):NULL,sig_rl_size,
		(OPT_ISSET(flags, OPT_NONCE)) ? &qe_report : NULL, 
		quote, sz);

	
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_get_quote: %08x\n", status);
		return 1;
	}
	b64quote= base64_encode((char *) quote, sz);
	return 0;
}

int get_sigrl (IAS_Connection *ias, int version, sgx_epid_group_id_t gid,
	char **sig_rl, uint32_t *sig_rl_size)
{
	IAS_Request *req= NULL;
	int oops= 1;
	string sigrlstr;

	try {
		oops= 0;
		req= new IAS_Request(ias, (uint16_t) version);
	}
	catch (...) {
		oops = 1;
	}

	if (oops) {
		eprintf("Exception while creating IAS request object\n");
		return 0;
	}

	if ( req->sigrl(*(uint32_t *) gid, sigrlstr) != IAS_OK ) {
		return 0;
	}

	*sig_rl= strdup(sigrlstr.c_str());
	if ( *sig_rl == NULL ) return 0;

	*sig_rl_size= (uint32_t ) sigrlstr.length();

	return 1;
}
int get_attestation_report(IAS_Connection *ias, int version,
	const char *b64quote, const char* b64manifest,
	int strict_trust)
{
	IAS_Request *req = NULL;
	map<string,string> payload;
	vector<string> messages;
	ias_error_t status;
	string content;

	try {
		req= new IAS_Request(ias, (uint16_t) version);
	}
	catch (...) {
		eprintf("Exception while creating IAS request object\n");
		return 0;
	}

	payload.insert(make_pair("isvEnclaveQuote", b64quote));
		status= req->report(payload, content, messages,fulltext);
	if ( status == IAS_OK ) {
		JSON reportObj = JSON::Load(content);

		if ( verbose ) {
			edividerWithText("Report Body");
			eprintf("%s\n", content.c_str());
			edivider();
			if ( messages.size() ) {
				edividerWithText("IAS Advisories");
				for (vector<string>::const_iterator i = messages.begin();
					i != messages.end(); ++i ) {

					eprintf("%s\n", i->c_str());
				}
				edivider();
			}
		}

		if ( verbose ) {
			edividerWithText("IAS Report - JSON - Required Fields");
			if ( version >= 3 ) {
				eprintf("version               = %d\n",
					reportObj["version"].ToInt());
			}
			eprintf("id:                   = %s\n",
				reportObj["id"].ToString().c_str());
			eprintf("timestamp             = %s\n",
				reportObj["timestamp"].ToString().c_str());
			eprintf("isvEnclaveQuoteStatus = %s\n",
				reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
			eprintf("isvEnclaveQuoteBody   = %s\n",
				reportObj["isvEnclaveQuoteBody"].ToString().c_str());

			edividerWithText("IAS Report - JSON - Optional Fields");

			eprintf("platformInfoBlob  = %s\n",
				reportObj["platformInfoBlob"].ToString().c_str());
			eprintf("revocationReason  = %s\n",
				reportObj["revocationReason"].ToString().c_str());
			eprintf("pseManifestStatus = %s\n",
				reportObj["pseManifestStatus"].ToString().c_str());
			eprintf("pseManifestHash   = %s\n",
				reportObj["pseManifestHash"].ToString().c_str());
			eprintf("nonce             = %s\n",
				reportObj["nonce"].ToString().c_str());
			eprintf("epidPseudonym     = %s\n",
				reportObj["epidPseudonym"].ToString().c_str());
			edivider();
		}

    /*
     * If the report returned a version number (API v3 and above), make
     * sure it matches the API version we used to fetch the report.
	 *
	 * For API v3 and up, this field MUST be in the report.
     */

		if ( reportObj.hasKey("version") ) {
			unsigned int rversion= (unsigned int) reportObj["version"].ToInt();
			if ( verbose )
				eprintf("+++ Verifying report version against API version\n");
			if ( version != rversion ) {
				eprintf("Report version %u does not match API version %u\n",
					rversion , version);
				return 0;
			}
		} else if ( version >= 3 ) {
			eprintf("attestation report version required for API version >= 3\n");
			return 0;
		}


                 
		return 1;
	}

	eprintf("attestation query returned %lu: \n", status);

	switch(status) {
		case IAS_QUERY_FAILED:
			eprintf("Could not query IAS\n");
			break;
		case IAS_BADREQUEST:
			eprintf("Invalid payload\n");
			break;
		case IAS_UNAUTHORIZED:
			eprintf("Failed to authenticate or authorize request\n");
			break;
		case IAS_SERVER_ERR:
			eprintf("An internal error occurred on the IAS server\n");
			break;
		case IAS_UNAVAILABLE:
			eprintf("Service is currently not able to process the request. Try again later.\n");
			break;
		case IAS_INTERNAL_ERROR:
			eprintf("An internal error occurred while processing the IAS response\n");
			break;
		case IAS_BAD_CERTIFICATE:
			eprintf("The signing certificate could not be validated\n");
			break;
		case IAS_BAD_SIGNATURE:
			eprintf("The report signature could not be validated\n");
			break;
		default:
			if ( status >= 100 && status < 600 ) {
				eprintf("Unexpected HTTP response code\n");
			} else {
				eprintf("An unknown error occurred.\n");
			}
	}

	return 0;
}
/*
 * Search for the enclave file and then try and load it.
 */


sgx_status_t sgx_create_enclave_search (const char *filename, const int edebug,
	sgx_launch_token_t *token, int *updated, sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr)
{
	struct stat sb;
	char epath[PATH_MAX];	/* includes NULL */

	/* Is filename an absolute path? */

	if ( filename[0] == '/' ) 
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);

	/* Is the enclave in the current working directory? */

	if ( stat(filename, &sb) == 0 )
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);

	/* Search the paths in LD_LBRARY_PATH */

	if ( file_in_searchpath(filename, getenv("LD_LIBRARY_PATH"), epath, PATH_MAX) )
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);
		
	/* Search the paths in DT_RUNPATH */

	if ( file_in_searchpath(filename, getenv("DT_RUNPATH"), epath, PATH_MAX) )
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

	/* Standard system library paths */

	if ( file_in_searchpath(filename, DEF_LIB_SEARCHPATH, epath, PATH_MAX) )
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

	/*
	 * If we've made it this far then we don't know where else to look.
	 * Just call sgx_create_enclave() which assumes the enclave is in
	 * the current working directory. This is almost guaranteed to fail,
	 * but it will insure we are consistent about the error codes that
	 * get reported to the calling function.
	 */

	return sgx_create_enclave(filename, edebug, token, updated, eid, attr);
}

int file_in_searchpath (const char *file, const char *search, char *fullpath, 
	size_t len)
{
	char *p, *str;
	size_t rem;
	struct stat sb;

	if ( search == NULL ) return 0;
	if ( strlen(search) == 0 ) return 0;

	str= strdup(search);
	if ( str == NULL ) return 0;

	p= strtok(str, ":");
	while ( p != NULL) {
		size_t lp= strlen(p);

		if ( lp ) {

			strncpy(fullpath, p, len);
			rem= len-lp-1;

			strncat(fullpath, "/", rem);
			--rem;

			strncat(fullpath, file, rem);

			if ( stat(fullpath, &sb) == 0 ) {
				free(str);
				return 1;
			}
		}

		p= strtok(NULL, ":");
	}

	free(str);

	return 0;
}



void usage () 
{
	fprintf(stderr, "usage: client [ options ] [ host[:port] ]\n\n");
	fprintf(stderr, "Required:\n");
	fprintf(stderr, "  -N, --nonce-file=FILE    Set a nonce from a file containing a 32-byte\n");
	fprintf(stderr, "                             ASCII hex string\n");
	fprintf(stderr, "  -P, --pubkey-file=FILE   File containing the public key of the service\n");
	fprintf(stderr, "                             provider.\n");
	fprintf(stderr, "  -S, --spid-file=FILE     Set the SPID from a file containing a 32-byte\n");
	fprintf(stderr, "                             ASCII hex string\n");
	fprintf(stderr, "  -d, --debug              Show debugging information\n");
	fprintf(stderr, "  -e, --epid-gid           Get the EPID Group ID instead of performing\n");
	fprintf(stderr, "                             an attestation.\n");
	fprintf(stderr, "  -l, --linkable           Specify a linkable quote (default: unlinkable)\n");
	fprintf(stderr, "  -m, --pse-manifest       Include the PSE manifest in the quote\n");
	fprintf(stderr, "  -n, --nonce=HEXSTRING    Set a nonce from a 32-byte ASCII hex string\n");
	fprintf(stderr, "  -p, --pubkey=HEXSTRING   Specify the public key of the service provider\n");
	fprintf(stderr, "                             as an ASCII hex string instead of using the\n");
	fprintf(stderr, "                             default.\n");
	fprintf(stderr, "  -q                       Generate a quote instead of performing an\n");
	fprintf(stderr, "                             attestation.\n");
	fprintf(stderr, "  -r                       Generate a nonce using RDRAND\n");
	fprintf(stderr, "  -s, --spid=HEXSTRING     Set the SPID from a 32-byte ASCII hex string\n");
	fprintf(stderr, "  -v, --verbose            Print decoded RA messages to stderr\n");
	fprintf(stderr, "  -z                       Read from stdin and write to stdout instead\n");
	fprintf(stderr, "                             connecting to a server.\n");
	fprintf(stderr, "\nOne of --spid OR --spid-file is required for generating a quote or doing\nremote attestation.\n");
	exit(1);
}

