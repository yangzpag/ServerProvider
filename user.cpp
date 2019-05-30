#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <sgx_key_exchange.h>
#include <sgx_report.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "json.hpp"
#include "common.h"
#include "hexutil.h"
#include "fileio.h"
#include "crypto.h"
#include "byteorder.h"
#include "msgio.h"
#include "protocol.h"
#include "base64.h"
#include "iasrequest.h"
#include "logfile.h"
#include "settings.h"
#include "Enclave/client.h"
#include "httpparser/response.h"
#include "httpparser/httpresponseparser.h"

#define IAS_SIGNING_CAFILE  "IAS/AttestationReportSigningCACert.pem" 

using namespace json;
using namespace std;
using namespace httpparser;
#include <map>
#include <string>
#include <iostream>
#include <algorithm>
typedef struct config_struct{
	sgx_ec256_public_t pubkey;
	char *server;
	int port;
	uint8_t sk[16];
	uint8_t kdk[16];
	X509_STORE *store;
	X509 *signing_ca;
}config_t;

int derive_kdk(EVP_PKEY *Gb, unsigned char kdk[16], sgx_ec256_public_t g_a,
	config_t *config);
int parserReport(const Response &response,string &content,
        vector<string> &messages,config_t &config);
static string url_decode(string str);
int parserContent(string content,vector<string> messages,int version,sgx_quote_t * quote);
char buf[1024*1024]; 

char debug,verbose;
int main(){

	fplog = create_logfile("user.log");
	fprintf(fplog, "User log started\n");
	verbose = 0;
	config_t config;
	memset(&config,0,sizeof(config));

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

	struct sockaddr_in their_addr;
	int sockfd;
    	while((sockfd = socket(AF_INET,SOCK_STREAM,0)) == -1);

    	their_addr.sin_family = AF_INET;
    	their_addr.sin_port = htons(7777);
    	their_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    	bzero(&(their_addr.sin_zero), 8);

    	while(connect(sockfd,(struct sockaddr*)&their_addr,sizeof(struct sockaddr)) == -1);
	
	strcpy(buf,"hello");
	send(sockfd,buf,strlen(buf),0);
	
	//receive msg2 and verification evidence
	uint32_t rsz;
	rsz = read(sockfd, buf,1024*1024);
	client_dh_msg2_t msg2;
	uint32_t sz = sizeof(client_dh_msg2_t);

	memcpy((void *)&msg2,buf,sz);

	fprintf(stderr,"msg2.ga.gx = ");
        print_hexstring(stderr, msg2.ga.gx, 32);
        fprintf(stderr,"\n msg2.ga.gy = ");

        print_hexstring(stderr, msg2.ga.gy, 32);
        fprintf(stderr,"\n msg2.sig.x = ");

        print_hexstring(stderr, msg2.sig.x, 32);
        fprintf(stderr,"\n msg2.sig.y = ");

        print_hexstring(stderr, msg2.sig.y, 32);
	fprintf(stderr,"\n");

	string sresponse = buf + sz;
	
	if(verbose){
		 fprintf(stderr,"%s\n",sresponse.c_str());
	}
	Response response;
	HttpResponseParser parser;
	//parse verification
	HttpResponseParser::ParseResult result;
	result = parser.parse(response, sresponse.c_str(),
			sresponse.c_str()+sresponse.length());
	if(!(result == HttpResponseParser::ParsingCompleted))return -1;	
	
	string content;
	vector<string> messages;
	parserReport(response,content,messages,config);
	sgx_quote_t quote;
	parserContent(content,messages,IAS_API_DEF_VERSION,&quote);
	//fprintf(stderr,"version=%d sign_type = %d size=%d\n",quote.version,quote.sign_type,sizeof(quote));
	//EVP_PKEY *Ga;
	sgx_ec256_public_t service_pub_key;
	memcpy(&service_pub_key,&quote.report_body.report_data,64);
	fprintf(stderr,"\nservice_pubkey.gx = ");
        print_hexstring(stderr, service_pub_key.gx, 32);
        fprintf(stderr,"\nservice_pubkey.gy = ");

        print_hexstring(stderr, service_pub_key.gy, 32);

	size_t mlen = sizeof(sgx_ec256_public_t);
	if ( ! ecdsa_verify((uint8_t *)&msg2.ga,mlen,&service_pub_key,&msg2.sig)){
		eprintf("Could not validate signature\n");	
		
	}

	EVP_PKEY *Gb= key_generate();

	if ( ! derive_kdk(Gb, config.kdk, msg2.ga, &config) ) {
		eprintf("Could not derive the KDK\n");

		return 0;
	}

	eprintf("+++ KDK = %s\n", hexstring(config.kdk, 16));

	/*
 	 * Derive the SMK from the KDK
	 * SMK = AES_CMAC(KDK, 0x01 || "SMK" || 0x00 || 0x80 || 0x00)
	 */

	eprintf("+++ deriving SMK\n");

	cmac128(config.kdk, (unsigned char *)("\x01SMK\x00\x80\x00"), 7,
		config.sk);

	eprintf("+++ SMK = %s\n", hexstring(config.sk, 16));
	
	client_dh_msg3_t msg3;

	memset(&msg3,0,sizeof(client_dh_msg3_t));
	key_to_sgx_ec256(&msg3.gb, Gb);
	eprintf("+++ gb.gx = %s\n", hexstring(msg3.gb.gx, 32));
	eprintf("+++ gb.gy = %s\n", hexstring(msg3.gb.gy, 32));
	cmac128(config.sk, (unsigned char *) &msg3.gb, mlen,
		(unsigned char *) msg3.cmac);
	eprintf("+++ CMAC = %s\n", hexstring(msg3.cmac, 16));

	
	send(sockfd,&msg3,sizeof(client_dh_msg3_t),0);
	//fprintf(stderr,"\n%d\n",res);

	memset(buf,0,sizeof(buf));
	rsz = read(sockfd, buf,1024*1024);
	printf("%s\n",buf);
	int input=34;
	scanf("%d",&input);
/*	memset(buf,0,sizeof(buf));
	uint8_t iv[EVP_MAX_IV_LENGTH];
	memset((void*)iv, 'i', EVP_MAX_IV_LENGTH);
	uint8_t ubuf[1024*1024];

	aes_ctr_encrypt(config.sk,(uint8_t*)&input,sizeof(int),iv,ubuf);
	
	uint8_t plain[16];
	aes_ctr_decrypt(config.sk,ubuf ,16,iv,plain);

	printf("%s\n",hexstring(plain, 16));
	//send(sockfd,buf,strlen(buf));
*/
	send(sockfd,&input,4,0);
	rsz = read(sockfd, buf,1024*1024);
	int aaa;
	memcpy(&aaa,buf,4);
	printf("shouwld wait=%d\n",aaa);
	getchar();
	getchar();
	close(sockfd);
	return 0;
}

int parserContent(string content,vector<string> messages,int version,sgx_quote_t * quote){

	JSON reportObj = JSON::Load(content);


	size_t sz;
	char *quote_s = base64_decode(reportObj["isvEnclaveQuoteBody"].ToString().c_str(),&sz);
	fprintf(stderr,"base64_decode_size=%d",sz);
	memcpy(quote,quote_s,sz);
	free(quote_s);
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

int parserReport(const Response &response,string &content,
	vector<string> &messages,config_t& config){


	string certchain;
	string body= "{\n";
	size_t cstart, cend, count, i;
	vector<X509 *> certvec;
	X509 **certar;
	X509 *sign_cert;
	STACK_OF(X509) *stack;
	string sigstr, header;
	size_t sigsz;
	ias_error_t status;
	int rv;
	unsigned char *sig= NULL;
	EVP_PKEY *pkey= NULL;

	if ( response.statusCode != IAS_OK ) return response.statusCode;
	/*
	 * The response body has the attestation report. The headers have
	 * a signature of the report, and the public signing certificate.
	 * We need to:
	 *
	 * 1) Verify the certificate chain, to ensure it's issued by the
	 *    Intel CA (passed with the -A option).
	 *
	 * 2) Extract the public key from the signing cert, and verify
	 *    the signature.
	 */

	// Get the certificate chain from the headers
	
	certchain= response.headers_as_string("X-IASReport-Signing-Certificate");
	if ( certchain == "" ) {
		eprintf("Header X-IASReport-Signing-Certificate not found\n");
		return IAS_BAD_CERTIFICATE;
	}

	// URL decode
	try {
		certchain= url_decode(certchain);
	}
	catch (...) {
		eprintf("invalid URL encoding in header X-IASReport-Signing-Certificate\n");
		return IAS_BAD_CERTIFICATE;
	}

	// Build the cert stack. Find the positions in the string where we
	// have a BEGIN block.

	cstart= cend= 0;
	while (cend != string::npos ) {
		X509 *cert;
		size_t len;

		cend= certchain.find("-----BEGIN", cstart+1);
		len= ( (cend == string::npos) ? certchain.length() : cend )-cstart;

		if ( verbose ) {
			edividerWithText("Certficate");
			eputs(certchain.substr(cstart, len).c_str());
			eprintf("\n");
			edivider();
		}

		if ( ! cert_load(&cert, certchain.substr(cstart, len).c_str()) ) {
			crypto_perror("cert_load");
			return IAS_BAD_CERTIFICATE;
		}

		certvec.push_back(cert);
		cstart= cend;
	}

	count= certvec.size();
	if ( debug ) eprintf( "+++ Found %lu certificates in chain\n", count);

	certar= (X509**) malloc(sizeof(X509 *)*(count+1));
	if ( certar == 0 ) {
		perror("malloc");
		return IAS_INTERNAL_ERROR;
	}
	for (i= 0; i< count; ++i) certar[i]= certvec[i];
	certar[count]= NULL;

	// Create a STACK_OF(X509) stack from our certs

	stack= cert_stack_build(certar);
	if ( stack == NULL ) {
		crypto_perror("cert_stack_build");
		return IAS_INTERNAL_ERROR;
	}

	// Now verify the signing certificate

	rv= cert_verify(config.store, stack);

	if ( ! rv ) {
		crypto_perror("cert_stack_build");
		eprintf("certificate verification failure\n");
		status= IAS_BAD_CERTIFICATE;
		goto cleanup;
	} else {
		if ( debug ) eprintf("+++ certificate chain verified\n", rv);
	}

	// The signing cert is valid, so extract and verify the signature

	sigstr= response.headers_as_string("X-IASReport-Signature");
	if ( sigstr == "" ) {
		eprintf("Header X-IASReport-Signature not found\n");
		status= IAS_BAD_SIGNATURE;
		goto cleanup;
	}

	sig= (unsigned char *) base64_decode(sigstr.c_str(), &sigsz);
	if ( sig == NULL ) {
		eprintf("Could not decode signature\n");
		status= IAS_BAD_SIGNATURE;
		goto cleanup;
	}

	if ( verbose ) {
		edividerWithText("Report Signature");
		print_hexstring(stderr, sig, sigsz);
		if ( fplog != NULL ) print_hexstring(fplog, sig, sigsz);
		eprintf( "\n");
		edivider();
	}

	sign_cert= certvec[0]; /* The first cert in the list */

	/*
	 * The report body is SHA256 signed with the private key of the
	 * signing cert.  Extract the public key from the certificate and
	 * verify the signature.
	 */

	if ( debug ) eprintf("+++ Extracting public key from signing cert\n");
	pkey= X509_get_pubkey(sign_cert);
	if ( pkey == NULL ) {
		eprintf("Could not extract public key from certificate\n");
		free(sig);
		status= IAS_INTERNAL_ERROR;
		goto cleanup;
	}

	content= response.content_string();

	if ( debug ) {
		eprintf("+++ Verifying signature over report body\n");
		edividerWithText("Report");
		eputs(content.c_str());
		eprintf("\n");
		edivider();
		eprintf("Content-length: %lu bytes\n", response.content_string().length());
		edivider();
	}

	if ( ! sha256_verify((const unsigned char *) content.c_str(),
		content.length(), sig, sigsz, pkey, &rv) ) {

		free(sig);
		crypto_perror("sha256_verify");
		eprintf("Could not validate signature\n");
		status= IAS_BAD_SIGNATURE;
	} else {
		if ( rv ) {
			if ( verbose ) eprintf("+++ Signature verified\n");
			status= IAS_OK;
		} else {
			eprintf("Invalid report signature\n");
			status= IAS_BAD_SIGNATURE;
		}
	}

	/*
	 * Check for advisory headers
	 */

	header= response.headers_as_string("Advisory-URL");
	if ( header.length() ) messages.push_back(header);

	header= response.headers_as_string("Advisory-IDs");
	if ( header.length() ) messages.push_back(header);

cleanup:
	if ( pkey != NULL ) EVP_PKEY_free(pkey);
	cert_stack_free(stack);
	free(certar);
	for (i= 0; i<count; ++i) X509_free(certvec[i]);
	free(sig);

	return status;


}
int derive_kdk(EVP_PKEY *Gb, unsigned char kdk[16], sgx_ec256_public_t g_a,
	config_t *config)
{
	unsigned char *Gab_x;
	size_t slen;
	EVP_PKEY *Ga;
	unsigned char cmackey[16];

	memset(cmackey, 0, 16);

	/*
	 * Compute the shared secret using the peer's public key and a generated
	 * public/private key.
	 */

	Ga= key_from_sgx_ec256(&g_a);
	if ( Ga == NULL ) {
		crypto_perror("key_from_sgx_ec256");
		return 0;
	}

	/* The shared secret in a DH exchange is the x-coordinate of Gab */
	Gab_x= key_shared_secret(Gb, Ga, &slen);
	if ( Gab_x == NULL ) {
		crypto_perror("key_shared_secret");
		return 0;
	}

	/* We need it in little endian order, so reverse the bytes. */
	/* We'll do this in-place. */

	eprintf("+++ shared secret= %s\n", hexstring(Gab_x, slen));

	reverse_bytes(Gab_x, Gab_x, slen);

	eprintf("+++ reversed     = %s\n", hexstring(Gab_x, slen));

	/* Now hash that to get our KDK (Key Definition Key) */

	/*
	 * KDK = AES_CMAC(0x00000000000000000000000000000000, secret)
	 */

	cmac128(cmackey, Gab_x, slen, kdk);

	return 1;
}
static string url_decode(string str)
{
	string decoded;
	size_t i;
	size_t len= str.length();

	for (i= 0; i< len; ++i) {
		if ( str[i] == '+' ) decoded+= ' ';
		else if ( str[i] == '%' ) {
			char *e= NULL;
			unsigned long int v;

			// Have a % but run out of characters in the string

			if ( i+3 > len ) throw std::length_error("premature end of string");

			v= strtoul(str.substr(i+1, 2).c_str(), &e, 16);

			// Have %hh but hh is not a valid hex code.
			if ( *e ) throw std::out_of_range("invalid encoding");

			decoded+= static_cast<char>(v);
			i+= 2;
		} else decoded+= str[i];
	}

	return decoded;
}
