#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_enclave_initalize_t {
	sgx_ec256_public_t* ms_cpubkey;
	sgx_ec256_private_t* ms_cprikey;
} ms_enclave_initalize_t;

typedef struct ms_enclave_add_client_t {
	int* ms_fd;
} ms_enclave_add_client_t;

typedef struct ms_enclave_get_client_status_t {
	int* ms_fd;
	ClientStatus* ms_cstatus;
} ms_enclave_get_client_status_t;

typedef struct ms_enclave_set_client_status_t {
	int* ms_fd;
	ClientStatus* ms_cstatus;
} ms_enclave_set_client_status_t;

typedef struct ms_enclave_generate_msg2_t {
	int* ms_fd;
	client_dh_msg2_t* ms_msg2;
	uint8_t* ms_res;
} ms_enclave_generate_msg2_t;

typedef struct ms_enclave_process_msg3_t {
	int* ms_fd;
	client_dh_msg3_t* ms_msg3;
	uint8_t* ms_res;
} ms_enclave_process_msg3_t;

typedef struct ms_enclave_cal_ava_t {
	int* ms_ok;
	int* ms_avg;
} ms_enclave_cal_ava_t;

typedef struct ms_enclave_process_clientdata_t {
	int* ms_fd;
	int* ms_num;
	uint32_t* ms_shoudwait;
} ms_enclave_process_clientdata_t;

typedef struct ms_get_report_t {
	sgx_status_t ms_retval;
	sgx_report_t* ms_report;
	sgx_target_info_t* ms_target_info;
} ms_get_report_t;

typedef struct ms_enclave_get_ps_sec_prop_t {
	sgx_status_t ms_retval;
	sgx_ps_sec_prop_desc_t* ms_security_property;
} ms_enclave_get_ps_sec_prop_t;

typedef struct ms_get_pse_manifest_size_t {
	size_t ms_retval;
} ms_get_pse_manifest_size_t;

typedef struct ms_get_pse_manifest_t {
	sgx_status_t ms_retval;
	char* ms_buf;
	size_t ms_sz;
} ms_get_pse_manifest_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	const sgx_ra_msg2_t* ms_p_msg2;
	const sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL sgx_enclave_initalize(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_initalize_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_initalize_t* ms = SGX_CAST(ms_enclave_initalize_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_cpubkey = ms->ms_cpubkey;
	size_t _len_cpubkey = sizeof(sgx_ec256_public_t);
	sgx_ec256_public_t* _in_cpubkey = NULL;
	sgx_ec256_private_t* _tmp_cprikey = ms->ms_cprikey;
	size_t _len_cprikey = sizeof(sgx_ec256_private_t);
	sgx_ec256_private_t* _in_cprikey = NULL;

	CHECK_UNIQUE_POINTER(_tmp_cpubkey, _len_cpubkey);
	CHECK_UNIQUE_POINTER(_tmp_cprikey, _len_cprikey);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_cpubkey != NULL && _len_cpubkey != 0) {
		if ((_in_cpubkey = (sgx_ec256_public_t*)malloc(_len_cpubkey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_cpubkey, 0, _len_cpubkey);
	}
	if (_tmp_cprikey != NULL && _len_cprikey != 0) {
		if ((_in_cprikey = (sgx_ec256_private_t*)malloc(_len_cprikey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_cprikey, 0, _len_cprikey);
	}

	enclave_initalize(_in_cpubkey, _in_cprikey);
err:
	if (_in_cpubkey) {
		if (memcpy_s(_tmp_cpubkey, _len_cpubkey, _in_cpubkey, _len_cpubkey)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_cpubkey);
	}
	if (_in_cprikey) {
		if (memcpy_s(_tmp_cprikey, _len_cprikey, _in_cprikey, _len_cprikey)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_cprikey);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_add_client(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_add_client_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_add_client_t* ms = SGX_CAST(ms_enclave_add_client_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_fd = ms->ms_fd;
	size_t _len_fd = sizeof(int);
	int* _in_fd = NULL;

	CHECK_UNIQUE_POINTER(_tmp_fd, _len_fd);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_fd != NULL && _len_fd != 0) {
		_in_fd = (int*)malloc(_len_fd);
		if (_in_fd == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_fd, _len_fd, _tmp_fd, _len_fd)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	enclave_add_client(_in_fd);
err:
	if (_in_fd) free(_in_fd);

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_get_client_status(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_get_client_status_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_get_client_status_t* ms = SGX_CAST(ms_enclave_get_client_status_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_fd = ms->ms_fd;
	size_t _len_fd = sizeof(int);
	int* _in_fd = NULL;
	ClientStatus* _tmp_cstatus = ms->ms_cstatus;
	size_t _len_cstatus = sizeof(ClientStatus);
	ClientStatus* _in_cstatus = NULL;

	CHECK_UNIQUE_POINTER(_tmp_fd, _len_fd);
	CHECK_UNIQUE_POINTER(_tmp_cstatus, _len_cstatus);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_fd != NULL && _len_fd != 0) {
		_in_fd = (int*)malloc(_len_fd);
		if (_in_fd == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_fd, _len_fd, _tmp_fd, _len_fd)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_cstatus != NULL && _len_cstatus != 0) {
		if ((_in_cstatus = (ClientStatus*)malloc(_len_cstatus)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_cstatus, 0, _len_cstatus);
	}

	enclave_get_client_status(_in_fd, _in_cstatus);
err:
	if (_in_fd) free(_in_fd);
	if (_in_cstatus) {
		if (memcpy_s(_tmp_cstatus, _len_cstatus, _in_cstatus, _len_cstatus)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_cstatus);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_set_client_status(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_set_client_status_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_set_client_status_t* ms = SGX_CAST(ms_enclave_set_client_status_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_fd = ms->ms_fd;
	size_t _len_fd = sizeof(int);
	int* _in_fd = NULL;
	ClientStatus* _tmp_cstatus = ms->ms_cstatus;
	size_t _len_cstatus = sizeof(ClientStatus);
	ClientStatus* _in_cstatus = NULL;

	CHECK_UNIQUE_POINTER(_tmp_fd, _len_fd);
	CHECK_UNIQUE_POINTER(_tmp_cstatus, _len_cstatus);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_fd != NULL && _len_fd != 0) {
		_in_fd = (int*)malloc(_len_fd);
		if (_in_fd == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_fd, _len_fd, _tmp_fd, _len_fd)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_cstatus != NULL && _len_cstatus != 0) {
		_in_cstatus = (ClientStatus*)malloc(_len_cstatus);
		if (_in_cstatus == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_cstatus, _len_cstatus, _tmp_cstatus, _len_cstatus)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	enclave_set_client_status(_in_fd, _in_cstatus);
err:
	if (_in_fd) free(_in_fd);
	if (_in_cstatus) free(_in_cstatus);

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_generate_msg2(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_generate_msg2_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_generate_msg2_t* ms = SGX_CAST(ms_enclave_generate_msg2_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_fd = ms->ms_fd;
	size_t _len_fd = sizeof(int);
	int* _in_fd = NULL;
	client_dh_msg2_t* _tmp_msg2 = ms->ms_msg2;
	size_t _len_msg2 = sizeof(client_dh_msg2_t);
	client_dh_msg2_t* _in_msg2 = NULL;
	uint8_t* _tmp_res = ms->ms_res;
	size_t _len_res = sizeof(uint8_t);
	uint8_t* _in_res = NULL;

	CHECK_UNIQUE_POINTER(_tmp_fd, _len_fd);
	CHECK_UNIQUE_POINTER(_tmp_msg2, _len_msg2);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_fd != NULL && _len_fd != 0) {
		_in_fd = (int*)malloc(_len_fd);
		if (_in_fd == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_fd, _len_fd, _tmp_fd, _len_fd)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_msg2 != NULL && _len_msg2 != 0) {
		if ((_in_msg2 = (client_dh_msg2_t*)malloc(_len_msg2)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_msg2, 0, _len_msg2);
	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (uint8_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}

	enclave_generate_msg2(_in_fd, _in_msg2, _in_res);
err:
	if (_in_fd) free(_in_fd);
	if (_in_msg2) {
		if (memcpy_s(_tmp_msg2, _len_msg2, _in_msg2, _len_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_msg2);
	}
	if (_in_res) {
		if (memcpy_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_res);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_process_msg3(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_process_msg3_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_process_msg3_t* ms = SGX_CAST(ms_enclave_process_msg3_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_fd = ms->ms_fd;
	size_t _len_fd = sizeof(int);
	int* _in_fd = NULL;
	client_dh_msg3_t* _tmp_msg3 = ms->ms_msg3;
	size_t _len_msg3 = sizeof(client_dh_msg3_t);
	client_dh_msg3_t* _in_msg3 = NULL;
	uint8_t* _tmp_res = ms->ms_res;
	size_t _len_res = sizeof(uint8_t);
	uint8_t* _in_res = NULL;

	CHECK_UNIQUE_POINTER(_tmp_fd, _len_fd);
	CHECK_UNIQUE_POINTER(_tmp_msg3, _len_msg3);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_fd != NULL && _len_fd != 0) {
		_in_fd = (int*)malloc(_len_fd);
		if (_in_fd == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_fd, _len_fd, _tmp_fd, _len_fd)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_msg3 != NULL && _len_msg3 != 0) {
		_in_msg3 = (client_dh_msg3_t*)malloc(_len_msg3);
		if (_in_msg3 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_msg3, _len_msg3, _tmp_msg3, _len_msg3)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ((_in_res = (uint8_t*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}

	enclave_process_msg3(_in_fd, _in_msg3, _in_res);
err:
	if (_in_fd) free(_in_fd);
	if (_in_msg3) free(_in_msg3);
	if (_in_res) {
		if (memcpy_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_res);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_cal_ava(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_cal_ava_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_cal_ava_t* ms = SGX_CAST(ms_enclave_cal_ava_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_ok = ms->ms_ok;
	size_t _len_ok = sizeof(int);
	int* _in_ok = NULL;
	int* _tmp_avg = ms->ms_avg;
	size_t _len_avg = sizeof(int);
	int* _in_avg = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ok, _len_ok);
	CHECK_UNIQUE_POINTER(_tmp_avg, _len_avg);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ok != NULL && _len_ok != 0) {
		if ((_in_ok = (int*)malloc(_len_ok)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ok, 0, _len_ok);
	}
	if (_tmp_avg != NULL && _len_avg != 0) {
		if ((_in_avg = (int*)malloc(_len_avg)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_avg, 0, _len_avg);
	}

	enclave_cal_ava(_in_ok, _in_avg);
err:
	if (_in_ok) {
		if (memcpy_s(_tmp_ok, _len_ok, _in_ok, _len_ok)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_ok);
	}
	if (_in_avg) {
		if (memcpy_s(_tmp_avg, _len_avg, _in_avg, _len_avg)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_avg);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_process_clientdata(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_process_clientdata_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_process_clientdata_t* ms = SGX_CAST(ms_enclave_process_clientdata_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_fd = ms->ms_fd;
	size_t _len_fd = sizeof(int);
	int* _in_fd = NULL;
	int* _tmp_num = ms->ms_num;
	size_t _len_num = sizeof(int);
	int* _in_num = NULL;
	uint32_t* _tmp_shoudwait = ms->ms_shoudwait;
	size_t _len_shoudwait = sizeof(uint32_t);
	uint32_t* _in_shoudwait = NULL;

	CHECK_UNIQUE_POINTER(_tmp_fd, _len_fd);
	CHECK_UNIQUE_POINTER(_tmp_num, _len_num);
	CHECK_UNIQUE_POINTER(_tmp_shoudwait, _len_shoudwait);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_fd != NULL && _len_fd != 0) {
		_in_fd = (int*)malloc(_len_fd);
		if (_in_fd == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_fd, _len_fd, _tmp_fd, _len_fd)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_num != NULL && _len_num != 0) {
		_in_num = (int*)malloc(_len_num);
		if (_in_num == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_num, _len_num, _tmp_num, _len_num)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_shoudwait != NULL && _len_shoudwait != 0) {
		if ((_in_shoudwait = (uint32_t*)malloc(_len_shoudwait)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_shoudwait, 0, _len_shoudwait);
	}

	enclave_process_clientdata(_in_fd, _in_num, _in_shoudwait);
err:
	if (_in_fd) free(_in_fd);
	if (_in_num) free(_in_num);
	if (_in_shoudwait) {
		if (memcpy_s(_tmp_shoudwait, _len_shoudwait, _in_shoudwait, _len_shoudwait)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_shoudwait);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_get_report(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_report_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_report_t* ms = SGX_CAST(ms_get_report_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_report = ms->ms_report;
	size_t _len_report = sizeof(sgx_report_t);
	sgx_report_t* _in_report = NULL;
	sgx_target_info_t* _tmp_target_info = ms->ms_target_info;
	size_t _len_target_info = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_target_info = NULL;

	CHECK_UNIQUE_POINTER(_tmp_report, _len_report);
	CHECK_UNIQUE_POINTER(_tmp_target_info, _len_target_info);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_report != NULL && _len_report != 0) {
		if ((_in_report = (sgx_report_t*)malloc(_len_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_report, 0, _len_report);
	}
	if (_tmp_target_info != NULL && _len_target_info != 0) {
		_in_target_info = (sgx_target_info_t*)malloc(_len_target_info);
		if (_in_target_info == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_target_info, _len_target_info, _tmp_target_info, _len_target_info)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = get_report(_in_report, _in_target_info);
err:
	if (_in_report) {
		if (memcpy_s(_tmp_report, _len_report, _in_report, _len_report)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_report);
	}
	if (_in_target_info) free(_in_target_info);

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_get_ps_sec_prop(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_get_ps_sec_prop_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_get_ps_sec_prop_t* ms = SGX_CAST(ms_enclave_get_ps_sec_prop_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ps_sec_prop_desc_t* _tmp_security_property = ms->ms_security_property;
	size_t _len_security_property = sizeof(sgx_ps_sec_prop_desc_t);
	sgx_ps_sec_prop_desc_t* _in_security_property = NULL;

	CHECK_UNIQUE_POINTER(_tmp_security_property, _len_security_property);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_security_property != NULL && _len_security_property != 0) {
		if ((_in_security_property = (sgx_ps_sec_prop_desc_t*)malloc(_len_security_property)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_security_property, 0, _len_security_property);
	}

	ms->ms_retval = enclave_get_ps_sec_prop(_in_security_property);
err:
	if (_in_security_property) {
		if (memcpy_s(_tmp_security_property, _len_security_property, _in_security_property, _len_security_property)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_security_property);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_get_pse_manifest_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_pse_manifest_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_pse_manifest_size_t* ms = SGX_CAST(ms_get_pse_manifest_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = get_pse_manifest_size();


	return status;
}

static sgx_status_t SGX_CDECL sgx_get_pse_manifest(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_pse_manifest_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_pse_manifest_t* ms = SGX_CAST(ms_get_pse_manifest_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buf = ms->ms_buf;
	size_t _tmp_sz = ms->ms_sz;
	size_t _len_buf = _tmp_sz * sizeof(char);
	char* _in_buf = NULL;

	if (sizeof(*_tmp_buf) != 0 &&
		(size_t)_tmp_sz > (SIZE_MAX / sizeof(*_tmp_buf))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ((_in_buf = (char*)malloc(_len_buf)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_buf, 0, _len_buf);
	}

	ms->ms_retval = get_pse_manifest(_in_buf, _tmp_sz);
err:
	if (_in_buf) {
		if (memcpy_s(_tmp_buf, _len_buf, _in_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_buf);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_ga(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_ga_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_ga_t* ms = SGX_CAST(ms_sgx_ra_get_ga_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = ms->ms_g_a;
	size_t _len_g_a = sizeof(sgx_ec256_public_t);
	sgx_ec256_public_t* _in_g_a = NULL;

	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_g_a != NULL && _len_g_a != 0) {
		if ((_in_g_a = (sgx_ec256_public_t*)malloc(_len_g_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_a, 0, _len_g_a);
	}

	ms->ms_retval = sgx_ra_get_ga(ms->ms_context, _in_g_a);
err:
	if (_in_g_a) {
		if (memcpy_s(_tmp_g_a, _len_g_a, _in_g_a, _len_g_a)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_g_a);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_proc_msg2_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_proc_msg2_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_proc_msg2_trusted_t* ms = SGX_CAST(ms_sgx_ra_proc_msg2_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const sgx_ra_msg2_t* _tmp_p_msg2 = ms->ms_p_msg2;
	size_t _len_p_msg2 = sizeof(sgx_ra_msg2_t);
	sgx_ra_msg2_t* _in_p_msg2 = NULL;
	const sgx_target_info_t* _tmp_p_qe_target = ms->ms_p_qe_target;
	size_t _len_p_qe_target = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_p_qe_target = NULL;
	sgx_report_t* _tmp_p_report = ms->ms_p_report;
	size_t _len_p_report = sizeof(sgx_report_t);
	sgx_report_t* _in_p_report = NULL;
	sgx_quote_nonce_t* _tmp_p_nonce = ms->ms_p_nonce;
	size_t _len_p_nonce = sizeof(sgx_quote_nonce_t);
	sgx_quote_nonce_t* _in_p_nonce = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_msg2, _len_p_msg2);
	CHECK_UNIQUE_POINTER(_tmp_p_qe_target, _len_p_qe_target);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);
	CHECK_UNIQUE_POINTER(_tmp_p_nonce, _len_p_nonce);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_msg2 != NULL && _len_p_msg2 != 0) {
		_in_p_msg2 = (sgx_ra_msg2_t*)malloc(_len_p_msg2);
		if (_in_p_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_msg2, _len_p_msg2, _tmp_p_msg2, _len_p_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_qe_target != NULL && _len_p_qe_target != 0) {
		_in_p_qe_target = (sgx_target_info_t*)malloc(_len_p_qe_target);
		if (_in_p_qe_target == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_qe_target, _len_p_qe_target, _tmp_p_qe_target, _len_p_qe_target)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_report != NULL && _len_p_report != 0) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}
	if (_tmp_p_nonce != NULL && _len_p_nonce != 0) {
		if ((_in_p_nonce = (sgx_quote_nonce_t*)malloc(_len_p_nonce)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_nonce, 0, _len_p_nonce);
	}

	ms->ms_retval = sgx_ra_proc_msg2_trusted(ms->ms_context, (const sgx_ra_msg2_t*)_in_p_msg2, (const sgx_target_info_t*)_in_p_qe_target, _in_p_report, _in_p_nonce);
err:
	if (_in_p_msg2) free(_in_p_msg2);
	if (_in_p_qe_target) free(_in_p_qe_target);
	if (_in_p_report) {
		if (memcpy_s(_tmp_p_report, _len_p_report, _in_p_report, _len_p_report)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_p_report);
	}
	if (_in_p_nonce) {
		if (memcpy_s(_tmp_p_nonce, _len_p_nonce, _in_p_nonce, _len_p_nonce)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_p_nonce);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_msg3_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_msg3_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_msg3_trusted_t* ms = SGX_CAST(ms_sgx_ra_get_msg3_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_qe_report = ms->ms_qe_report;
	size_t _len_qe_report = sizeof(sgx_report_t);
	sgx_report_t* _in_qe_report = NULL;
	sgx_ra_msg3_t* _tmp_p_msg3 = ms->ms_p_msg3;

	CHECK_UNIQUE_POINTER(_tmp_qe_report, _len_qe_report);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_qe_report != NULL && _len_qe_report != 0) {
		_in_qe_report = (sgx_report_t*)malloc(_len_qe_report);
		if (_in_qe_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_qe_report, _len_qe_report, _tmp_qe_report, _len_qe_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = sgx_ra_get_msg3_trusted(ms->ms_context, ms->ms_quote_size, _in_qe_report, _tmp_p_msg3, ms->ms_msg3_size);
err:
	if (_in_qe_report) free(_in_qe_report);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[15];
} g_ecall_table = {
	15,
	{
		{(void*)(uintptr_t)sgx_enclave_initalize, 0},
		{(void*)(uintptr_t)sgx_enclave_add_client, 0},
		{(void*)(uintptr_t)sgx_enclave_get_client_status, 0},
		{(void*)(uintptr_t)sgx_enclave_set_client_status, 0},
		{(void*)(uintptr_t)sgx_enclave_generate_msg2, 0},
		{(void*)(uintptr_t)sgx_enclave_process_msg3, 0},
		{(void*)(uintptr_t)sgx_enclave_cal_ava, 0},
		{(void*)(uintptr_t)sgx_enclave_process_clientdata, 0},
		{(void*)(uintptr_t)sgx_get_report, 0},
		{(void*)(uintptr_t)sgx_enclave_get_ps_sec_prop, 0},
		{(void*)(uintptr_t)sgx_get_pse_manifest_size, 0},
		{(void*)(uintptr_t)sgx_get_pse_manifest, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_ga, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_proc_msg2_trusted, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_msg3_trusted, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[9][15];
} g_dyn_entry_table = {
	9,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sid = sizeof(uint32_t);
	size_t _len_dh_msg1 = dh_msg1_size;

	ms_create_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_create_session_ocall_t);
	void *__tmp = NULL;

	void *__tmp_sid = NULL;
	void *__tmp_dh_msg1 = NULL;

	CHECK_ENCLAVE_POINTER(sid, _len_sid);
	CHECK_ENCLAVE_POINTER(dh_msg1, _len_dh_msg1);

	ocalloc_size += (sid != NULL) ? _len_sid : 0;
	ocalloc_size += (dh_msg1 != NULL) ? _len_dh_msg1 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_create_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_create_session_ocall_t));
	ocalloc_size -= sizeof(ms_create_session_ocall_t);

	if (sid != NULL) {
		ms->ms_sid = (uint32_t*)__tmp;
		__tmp_sid = __tmp;
		memset(__tmp_sid, 0, _len_sid);
		__tmp = (void *)((size_t)__tmp + _len_sid);
		ocalloc_size -= _len_sid;
	} else {
		ms->ms_sid = NULL;
	}
	
	if (dh_msg1 != NULL) {
		ms->ms_dh_msg1 = (uint8_t*)__tmp;
		__tmp_dh_msg1 = __tmp;
		memset(__tmp_dh_msg1, 0, _len_dh_msg1);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg1);
		ocalloc_size -= _len_dh_msg1;
	} else {
		ms->ms_dh_msg1 = NULL;
	}
	
	ms->ms_dh_msg1_size = dh_msg1_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (sid) {
			if (memcpy_s((void*)sid, _len_sid, __tmp_sid, _len_sid)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (dh_msg1) {
			if (memcpy_s((void*)dh_msg1, _len_dh_msg1, __tmp_dh_msg1, _len_dh_msg1)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg2 = dh_msg2_size;
	size_t _len_dh_msg3 = dh_msg3_size;

	ms_exchange_report_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_exchange_report_ocall_t);
	void *__tmp = NULL;

	void *__tmp_dh_msg3 = NULL;

	CHECK_ENCLAVE_POINTER(dh_msg2, _len_dh_msg2);
	CHECK_ENCLAVE_POINTER(dh_msg3, _len_dh_msg3);

	ocalloc_size += (dh_msg2 != NULL) ? _len_dh_msg2 : 0;
	ocalloc_size += (dh_msg3 != NULL) ? _len_dh_msg3 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_exchange_report_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_exchange_report_ocall_t));
	ocalloc_size -= sizeof(ms_exchange_report_ocall_t);

	ms->ms_sid = sid;
	if (dh_msg2 != NULL) {
		ms->ms_dh_msg2 = (uint8_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, dh_msg2, _len_dh_msg2)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_dh_msg2);
		ocalloc_size -= _len_dh_msg2;
	} else {
		ms->ms_dh_msg2 = NULL;
	}
	
	ms->ms_dh_msg2_size = dh_msg2_size;
	if (dh_msg3 != NULL) {
		ms->ms_dh_msg3 = (uint8_t*)__tmp;
		__tmp_dh_msg3 = __tmp;
		memset(__tmp_dh_msg3, 0, _len_dh_msg3);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg3);
		ocalloc_size -= _len_dh_msg3;
	} else {
		ms->ms_dh_msg3 = NULL;
	}
	
	ms->ms_dh_msg3_size = dh_msg3_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (dh_msg3) {
			if (memcpy_s((void*)dh_msg3, _len_dh_msg3, __tmp_dh_msg3, _len_dh_msg3)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_close_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_close_session_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_close_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_close_session_ocall_t));
	ocalloc_size -= sizeof(ms_close_session_ocall_t);

	ms->ms_sid = sid;
	ms->ms_timeout = timeout;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pse_message_req = pse_message_req_size;
	size_t _len_pse_message_resp = pse_message_resp_size;

	ms_invoke_service_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_invoke_service_ocall_t);
	void *__tmp = NULL;

	void *__tmp_pse_message_resp = NULL;

	CHECK_ENCLAVE_POINTER(pse_message_req, _len_pse_message_req);
	CHECK_ENCLAVE_POINTER(pse_message_resp, _len_pse_message_resp);

	ocalloc_size += (pse_message_req != NULL) ? _len_pse_message_req : 0;
	ocalloc_size += (pse_message_resp != NULL) ? _len_pse_message_resp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_invoke_service_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_invoke_service_ocall_t));
	ocalloc_size -= sizeof(ms_invoke_service_ocall_t);

	if (pse_message_req != NULL) {
		ms->ms_pse_message_req = (uint8_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, pse_message_req, _len_pse_message_req)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pse_message_req);
		ocalloc_size -= _len_pse_message_req;
	} else {
		ms->ms_pse_message_req = NULL;
	}
	
	ms->ms_pse_message_req_size = pse_message_req_size;
	if (pse_message_resp != NULL) {
		ms->ms_pse_message_resp = (uint8_t*)__tmp;
		__tmp_pse_message_resp = __tmp;
		memset(__tmp_pse_message_resp, 0, _len_pse_message_resp);
		__tmp = (void *)((size_t)__tmp + _len_pse_message_resp);
		ocalloc_size -= _len_pse_message_resp;
	} else {
		ms->ms_pse_message_resp = NULL;
	}
	
	ms->ms_pse_message_resp_size = pse_message_resp_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (pse_message_resp) {
			if (memcpy_s((void*)pse_message_resp, _len_pse_message_resp, __tmp_pse_message_resp, _len_pse_message_resp)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	ocalloc_size += (cpuinfo != NULL) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	ocalloc_size += (waiters != NULL) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

