#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>
#define LEN 100 

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_UUID;
	uint32_t err_origin;
	char plain_text[LEN]={0,};
	char enc_text[LEN]={0,};
	char dec_text[LEN]={0,};
	int val, key;

	
	if(argc>3){
		printf("param error\n");
		return 0;
	}

	res = TEEC_InitializeContext(NULL, &ctx);
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	
	memset(&op, 0, sizeof(op));
	
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = plain_text;
	op.params[0].tmpref.size = LEN;

	if(!strcmp(argv[1],"-e")){
		//get enc Key, write to file.
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op,
				 &err_origin);

		memcpy(&key, op.params[0].tmpref.buffer, sizeof(int));
		FILE* fpw = fopen("./enc_key.txt","w");
		fprintf(fpw,"%d",key);
		fclose(fpw);

		//read file, send text to encrypter
		FILE* fpr = fopen(argv[2],"r"); 
		if(fpr == NULL){                 
			printf("file open error\n");
			exit(1);
		}
		fscanf(fpr,"%[^\n]s",plain_text);
		fclose(fpr);
		memcpy(op.params[0].tmpref.buffer, plain_text, sizeof(plain_text));

		
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 &err_origin);

		memcpy(enc_text, op.params[0].tmpref.buffer, sizeof(enc_text));
		FILE* fpw2 = fopen("./enc_text.txt","w");
		fprintf(fpw2,"%s",enc_text);
		fclose(fpw2);

	}else if(!strcmp(argv[1],"-d")){
		FILE* fpr = fopen("./enc_key.txt","r"); 
		if(fpr == NULL){                 
			printf("file open error\n");
			exit(1);
		}
		int enc_key;
		fscanf(fpr,"%d",&enc_key);
		fclose(fpr);
		memcpy(op.params[0].tmpref.buffer, &enc_key, sizeof(enc_key));
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op,
				 &err_origin);
		
		//read file, send text to decrypter
		FILE* fpr2 = fopen(argv[2],"r"); 
		if(fpr2 == NULL){                 
			printf("file open error\n");
			exit(1);
		}
		fscanf(fpr2,"%s",enc_text);
		fclose(fpr2);
		memcpy(op.params[0].tmpref.buffer, enc_text, sizeof(enc_key));
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);
		memcpy(dec_text, op.params[0].tmpref.buffer, sizeof(enc_text));

		FILE* fpw = fopen("./dec_text.txt","w");
		fprintf(fpw,"%s",dec_text);
		fclose(fpw);
	}
	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);
	return 0;
}
