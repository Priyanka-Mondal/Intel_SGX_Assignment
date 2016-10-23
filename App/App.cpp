#include <stdio.h>
#include <map>
#include "../Enclave1/Enclave1_u.h"
#include "../Enclave2/Enclave2_u.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/conf.h>
#include <string.h>

extern std::map<sgx_enclave_id_t, uint32_t>g_enclave_id_map;

sgx_enclave_id_t e1_enclave_id = 0;
sgx_enclave_id_t e2_enclave_id = 0;

#define ENCLAVE1_PATH "libenclave1.so"
#define ENCLAVE2_PATH "libenclave2.so"

uint32_t invoke_enclaves()
{
    uint32_t enclave_temp_no;
    int ret, launch_token_updated;
    sgx_launch_token_t launch_token;

    enclave_temp_no = 0;

    ret = sgx_create_enclave(ENCLAVE1_PATH, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &e1_enclave_id, NULL);
    //printf("Enclave1 with id %llx invoked",e1_enclave_id);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e1_enclave_id, enclave_temp_no));

    ret = sgx_create_enclave(ENCLAVE2_PATH, SGX_DEBUG_FLAG, &launch_token, &launch_token_updated, &e2_enclave_id, NULL);
    //printf("Enclave2 with id %llx invoked",e2_enclave_id);
    if (ret != SGX_SUCCESS) {
                return ret;
    }

    enclave_temp_no++;
    g_enclave_id_map.insert(std::pair<sgx_enclave_id_t, uint32_t>(e2_enclave_id, enclave_temp_no));

    return SGX_SUCCESS;
}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);	
  abort();
}


int encrypt(unsigned char *plaintext, int plaintext_len,  unsigned char *ciphertext)
{
	unsigned char *iv = (unsigned char *)"01234567890123456";
	unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
	EVP_CIPHER_CTX *ctx;
	int len, ciphertext_len;

	if(!(ctx = EVP_CIPHER_CTX_new())) 
		handleErrors();

	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();

	ciphertext_len = len;

	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext+len, &len)) 
		handleErrors();

	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;
}

int main()
{
    uint32_t ret_status1, ret_status2;
    sgx_status_t status1, status2;
    uint32_t secret_data;

    if(invoke_enclaves() != SGX_SUCCESS)
    {
        printf("\nFAILURE: Enclaves can not be invoked");
	return 0;
    }

    printf("\n\n\n=========================================");
    printf("\nEnclave1 - EnclaveID %llx",e1_enclave_id);
    printf("\nEnclave2 - EnclaveID %llx",e2_enclave_id);   
	do
	{
        //creating sessions
        status1 = Enclave1_createSession(e1_enclave_id, &ret_status1, e1_enclave_id, e2_enclave_id);
	status2 = Enclave2_createSession(e2_enclave_id, &ret_status2, e2_enclave_id, e1_enclave_id);

	    if(ret_status1==0 && ret_status2==0 && status1==SGX_SUCCESS && status2==SGX_SUCCESS)
	    	printf("\nSUCCESS: Secure two way session created between Enclave1 and Enclave2 \n");
	    else
	    {
		printf("\nFAILED TO CREATE SESSION\n");
		break;
	    }
     
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings(); 
  OPENSSL_config(NULL);

        // The below code sends messages between Enclave1 and Enclave2 
	char ch = 'y';
	while(ch == 'y' || ch == 'Y')
	{
		int choice = 0;
options:	printf("\nOPTIONS\n");
		printf("-------\n");
		printf("(0)=> Exit\n");
		printf("(1)=> Send message from Enclave1 to Enclave2\n");
		printf("(2)=> Send message from Enclave2 to Enclave1\n");
		printf("Enter your choice:");
		scanf("%d",&choice);
		getchar();
		if(choice == 1)
		{
			printf("\nEnter secret data to send from Enclave1 to Enclave2:");
			scanf("%d",&secret_data);
			char *str = (char *)malloc(30);
			sprintf(str,"%d",secret_data);
			unsigned char *plaintext = (unsigned char *)str;
			unsigned char *ciphertext = (unsigned char *) malloc(30);
			int ciphertext_len;
			printf("\nENCRYPTING...\n");
			ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), ciphertext);
			char data_c;
			uint32_t data;
			int length = strlen ((char *)ciphertext);
			int i;
			for(i=0;i<length;i++)
			{
				data_c = ciphertext[i];
				data = (uint32_t)data_c;
				status1 = Enclave1_send_message(e1_enclave_id, &ret_status1, e1_enclave_id, e2_enclave_id, data);
			}

			    if(ret_status1 ==0 && status1==SGX_SUCCESS )
			    	printf("\nSUCCESS: Encrypted Message sent from Enclave1 to Enclave2.");
			    else
			    {
				printf("\nFAILED:Message sending from Enclave1 to Enclave2 failed.");
				break;
			    }
		}
		else if(choice == 2)
		{
			printf("\nEnter secret data to send from Enclave2 to Enclave1:");
			scanf("%d",&secret_data);
			char *str = (char *)malloc(30);
			sprintf(str,"%d",secret_data);
			unsigned char *plaintext = (unsigned char *)str;
			unsigned char *ciphertext = (unsigned char *) malloc(30);
			int ciphertext_len;
			printf("\nENCRYPTING...\n");
			ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), ciphertext);
			char data_c;
			uint32_t data;
			int length = strlen ((char *)ciphertext);
			int i;
			for(i=0;i<length;i++)
			{
				data_c = ciphertext[i];
				data = (uint32_t)data_c;
				status2 = Enclave2_send_message(e2_enclave_id, &ret_status2, e2_enclave_id, e1_enclave_id, data);
			}
			    if(ret_status2==0 && status2==SGX_SUCCESS)
				printf("\nSUCCESS: Encrypted Message sent from Enclave2 to Enclave1.");
			    else
			    {
				printf("\nFAILED:Message sending from Enclave2 to Enclave1 failed.");
				break;
			    }
		}
		else if(choice == 0)
			goto exit;
		else
		{
			printf("\n[[BAD CHOICE]]\n");
			goto options;
		}
		printf("\n\nContinue sending messages?(y/n):",ch);
		getchar();
		scanf("%c",&ch);
		printf("\n\n\n");
	}

exit: 	
        //Closing Sessions
        status1 = Enclave1_closeSession(e1_enclave_id, &ret_status1, e1_enclave_id, e2_enclave_id);
	status2 = Enclave2_closeSession(e2_enclave_id, &ret_status2, e2_enclave_id, e1_enclave_id);
        
	    if(ret_status1 == 0 && ret_status2 == 0 && status1 == SGX_SUCCESS && status2 == SGX_SUCCESS)
                printf("\nSUCCESS: Session Closed.\n");
            
            else
            {
                printf("\nFAILED: Could not close sessions.\n");
                break;
            }
   
	}while(0);

sgx_destroy_enclave(e1_enclave_id);
sgx_destroy_enclave(e2_enclave_id);
return 0;
}
