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

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <myta.h>

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_MYTA_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char str[8]="\0\0\0\0\0\0\0\0";
	int len=64;
	int len2=2;
	FILE* fp;
	char filename[40];
	char filename2[40];
	char keyfile[40];
	char keytext[8]="\0\0\0\0\0\0\0\0";
	char route[100] = "../../root/";
	char route2[100] = "../../root/";
	char route3[100] = "../../root/";
	char route4[100] = "../../root/";

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_INOUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	op.params[1].tmpref.buffer = str;
	op.params[1].tmpref.size = len2;

if(strcmp(argv[1], "-e")==0) {

	printf("========================Encryption========================\n");
	//printf("Please Input Plaintext file : %s", argv[2]);
	//scanf("%[^\n]s", filename);
	strcpy(filename, argv[2]);
	strcat(route, filename);
	fp=fopen(route, "r");
	fread(plaintext, sizeof(plaintext), 1, fp);
	fclose(fp);
	memcpy(op.params[0].tmpref.buffer, plaintext, len);
	
	res = TEEC_InvokeCommand(&sess, TA_MYTA_CMD_ENC_VALUE, &op,
				 &err_origin);

	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	memcpy(ciphertext, op.params[0].tmpref.buffer, len);
	fp=fopen("../../root/ciphertext.txt", "w");
	fwrite(ciphertext, strlen(ciphertext), 1, fp);
	fclose(fp);
	//write encrpyted key
	strcpy(str, op.params[1].tmpref.buffer);
	fp=fopen("../../root/encryptedkey.txt", "w");
	if(str[1]=='\0'){
		str[1]='\n';
	} else if(str[2]=='\0') {
		str[2]='\n';
	}
	fwrite(str, sizeof(str), 1, fp);
	fclose(fp);
	printf("\n");
}
if(strcmp(argv[1], "-d")==0){
	printf("========================Decryption========================\n");
	//printf("Please Input Ciphertext file: %s\n", argv[2]);
	//scanf(" %[^\n]s", filename2);
	strcpy(filename2, argv[2]);
	strcat(route2, filename2);
	fp=fopen(route2, "r");
	fread(ciphertext, sizeof(ciphertext), 1, fp);
	fclose(fp);	
	memcpy(op.params[0].tmpref.buffer, ciphertext, len);

	//printf("Please Input key file: %s", argv[3]);
	//scanf(" %[^\n]s", keyfile);
	strcpy(keyfile, argv[3]);
	strcat(route3, keyfile);
	fp=fopen(route3, "r");
	fread(keytext, sizeof(keytext), 1, fp);
	//fgets(keytext, sizeof(keytext), fp);
	fclose(fp);	
	memcpy(op.params[1].tmpref.buffer, keytext, sizeof(keytext));

	res = TEEC_InvokeCommand(&sess, TA_MYTA_CMD_DEC_VALUE, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	memcpy(plaintext, op.params[0].tmpref.buffer, len);
	//printf("Plaintext : %s\n", plaintext);
	strcat(route4, "decryptedtext.txt");
	fp=fopen(route4, "w");
	fwrite(plaintext, sizeof(plaintext), 1, fp);
	fclose(fp);
	printf("\n");
}
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
