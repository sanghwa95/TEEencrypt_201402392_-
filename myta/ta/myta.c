/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <stdlib.h>
#include <myta.h>
#include <stdio.h>

int key;
int rootkey=3;
char encryptedkey[2];
char decryptedkey[2];
/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
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
		void __maybe_unused **sess_ctx)
{
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
	IMSG("Caesar cipher ...\n");

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
}

static TEE_Result enc_value(uint32_t param_types,
	TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	
	char * in2 = (char *)params[1].memref.buffer;
	
	char encrypted [64]={0,};

	DMSG("========================Encryption========================\n");
	DMSG ("Plaintext :  %s", in);
	memcpy(encrypted, in, in_len);

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
	//encrypt random key

	if(key>=20){
		encryptedkey[0]='a'+2;
		encryptedkey[1]='a'+(key-20);
	} else if(key>=10){
		encryptedkey[0]='a'+1;
		encryptedkey[1]='a'+(key-10);
	} else {
		encryptedkey[0]='a'+key;
		encryptedkey[1]='\0';
	}

	for(int i=0; i<2; i++){
		if(encryptedkey[i]=='\0')
			break;
		encryptedkey[i] -= 'a';
		encryptedkey[i] += rootkey;
		encryptedkey[i] = encryptedkey[i] % 26;
		encryptedkey[i] += 'a';
	}
	
	//params[1].memref.buffer = encryptedkey;

	DMSG ("Ciphertext :  %s", encrypted);
	DMSG ("key :  %d", key);
	DMSG ("Encrypted key :  %s", encryptedkey);
	memcpy(in, encrypted, in_len);
	memcpy(params[1].memref.buffer, encryptedkey, sizeof(encryptedkey));
	DMSG ("Encrypt Success!");

	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char decrypted [64]={0,};

	char * in2 = (char *)params[1].memref.buffer;
	int in_len2 = strlen (params[1].memref.buffer);

	DMSG("========================Decryption========================\n");
	DMSG ("Ciphertext :  %s", in);
	DMSG ("encrypted key :  %s", in2);
	memcpy(decrypted, in, in_len);
	strcpy(decryptedkey, in2);
	for(int i=0; i<2; i++){
		if(decryptedkey[i]>'z'||decryptedkey[i]<'a'){
			decryptedkey[i]='\0';
			break;
		}
		decryptedkey[i] -= 'a';
		decryptedkey[i] -= rootkey;
		decryptedkey[i] += 26;
		decryptedkey[i] = decryptedkey[i] % 26;
		decryptedkey[i] += 'a';
	}
	DMSG ("decrypted key :  %s", decryptedkey);
	key=0;
	for(int i=0; i<2; i++){
		if(decryptedkey[i]=='\0')
			break;
		if(i==1)
			key=key*10;
		key=key+(decryptedkey[i]-'a');
	}

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
	DMSG ("key :  %d", key);
	DMSG ("Plaintext :  %s", decrypted);
	memcpy(in, decrypted, in_len);

	return TEE_SUCCESS;
}
/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */
	key=0;
	while(key%26==0||key<1){//generate random key
		TEE_GenerateRandom(&key, sizeof(key));
		key=key%26;
	}
	switch (cmd_id) {
	case TA_MYTA_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_MYTA_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
