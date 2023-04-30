#include <stdio.h>
#include <string.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <TEEencrypt_ta.h>
/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
#define ROOTKEY 7
int random_uuid;
int DEC_key;
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx){	
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	DMSG("has been called");
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("\n\n===========TA===========\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("\n===========TA===========\n\n\n");
}

static TEE_Result enc_key(uint32_t param_types,
	TEE_Param params[4]){
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen(params[0].memref.buffer);
	int send_key;
	random_uuid = 0;
	TEE_GenerateRandom(&random_uuid, sizeof(int));
	if(random_uuid<0)random_uuid*=-1;
	random_uuid%=25;
	random_uuid+=1;
	IMSG("NEW KEY : %d", random_uuid);
	send_key=(random_uuid + ROOTKEY)%26;
	IMSG("DEC KEY : %d", send_key);
	memcpy(in, &send_key, sizeof(int));
	return TEE_SUCCESS;
}
static TEE_Result enc_value(uint32_t param_types,
	TEE_Param params[4]){
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char encrypted [64]={0,};
	memcpy(encrypted, in, in_len);
	int key=random_uuid;

	IMSG("N_TEXT : %s", encrypted);
	for(int i=0; i<in_len;i++){
		if(encrypted[i]>='a' && encrypted[i] <='z'){
			encrypted[i] -= 'a';
			encrypted[i] += key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'a';
		}
		else if (encrypted[i] >= 'A' && encrypted[i] <= 'Z') {
			encrypted[i] -= 'A';
			encrypted[i] += key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'A';
		}
	}
	IMSG("E_TEXT : %s", encrypted);
	memcpy(in, encrypted, in_len);
	return TEE_SUCCESS;
}
static TEE_Result get_key(uint32_t param_types,
	TEE_Param params[4]){
	int recv_key;
	
	memcpy(&recv_key, params[0].memref.buffer, sizeof(int));
	IMSG("R_KEY: %d", recv_key);
	DEC_key=recv_key-ROOTKEY;
	if(DEC_key<1)DEC_key+=26;
	IMSG("D_KEY : %d", DEC_key);
	return TEE_SUCCESS;
}
static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4]){
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char decrypted [64]={0,};
	memcpy(decrypted, in, in_len);
	int key=DEC_key;

	IMSG("E_TEXT : %s", decrypted);
	for(int i=0; i<in_len;i++){
		if(decrypted[i]>='a' && decrypted[i] <='z'){
			decrypted[i] -= 'a';
			decrypted[i] -= key;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'a';
		}
		else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
			decrypted[i] -= 'A';
			decrypted[i] -= key;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'A';
		}
	}
	IMSG("D_TEXT: %s", decrypted);
	memcpy(in, decrypted, in_len);
	return TEE_SUCCESS;
}

/*h
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_GET:
		return get_key(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_ENC:
		return enc_key(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
