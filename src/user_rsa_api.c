
#include <string.h>
#include "iot_crypto.h"
#include "id_rsa_public.pem.h"
#include "id_rsa_private.pem.h"


#include "mbedTLS_config.h"
#define MBEDTLS_PK_PARSE_C
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha256.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/platform.h>
#include <mbedtls/md.h>

const char *TAG = "[rsa_utils]";

#define ESP_LOGI(tag, fmt, arg...) printf(fmt "\n", ##arg)
#if 0
#define ESP_LOG_BUFFER_HEXDUMP(TAG, buf, len, ESP_LOG_INFO)\
do {\
	int i = len;\
	unsigned char *data = (unsigned char *)buf;\
	printf("(%p %d bytes): ", buf, len);\
	for (i = 0; i < len; i++) {\
		printf("%02X", data[i]);\
	}\
	printf("\n");\
} while(0)
#else
#define ESP_LOG_BUFFER_HEXDUMP(TAG, buf, len, ESP_LOG_INFO) do {} while(0)
#endif

static const unsigned char *g_private_key_pem = NULL;
static const unsigned char *g_public_key_pem = NULL;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;

int rsa_data_sign_verify_only(const unsigned char *digest, size_t digest_len, unsigned char *sign_data, size_t sign_len)
{
	int ret;

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    size_t keylen = strlen((const char *) g_public_key_pem);
    ret = mbedtls_pk_parse_public_key(&pk, g_public_key_pem, keylen + 1);
    if (ret != 0) {
        ESP_LOGI(TAG, "pass public key error");
    } else {
        ESP_LOGI(TAG, "pass public key success %p", sign_data);
        ESP_LOG_BUFFER_HEXDUMP(TAG, digest, digest_len, ESP_LOG_INFO);
    	ESP_LOG_BUFFER_HEXDUMP(TAG, sign_data, sign_len, ESP_LOG_INFO);
        ret = mbedtls_pk_verify( &pk, MBEDTLS_MD_NONE,
								digest, digest_len,
								sign_data, sign_len );
        if (ret != 0) {
             //char error_buf[100];
            //mbedtls_strerror(ret, error_buf, sizeof(error_buf));
            //ESP_LOGI(TAG, "rsa public encrypt error:%s", error_buf);
            ESP_LOGI(TAG, "public key verify fail %d %x", ret, -ret);
        } else {
        	ESP_LOGI(TAG, "public key verify ok");
        }
    }
    mbedtls_pk_free(&pk);
    
    return ret;
}

int rsa_public_sign_verify(const unsigned char *public_key_pem, const unsigned char *msg_data,
                       size_t msg_len, unsigned char *sign_data, size_t sign_len) 
{
    int ret;
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info;
    uint8_t digest[32];
    int sign_size = 256;

    mbedtls_md_init(&ctx);
    info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_setup(&ctx, info, 0);
    //printf("md info setup, name: %s, digest size: %d\n", mbedtls_md_get_name(info), mbedtls_md_get_size(info));

    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, msg_data, msg_len);
    mbedtls_md_finish(&ctx, digest);

    mbedtls_md_free(&ctx);   
	
	g_public_key_pem = public_key_pem;
    size_t digest_len = sizeof(digest);
    rsa_data_sign_verify_only(digest, digest_len, sign_data, sign_len);

    return 0;
}

int rsa_data_sign_only(const unsigned char *digest, size_t digest_len, unsigned char *sign_data, size_t *sign_len)
{
	int ret;

    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    size_t keylen = strlen((char *) g_private_key_pem);
    // 解析私钥
    ret = mbedtls_pk_parse_key(&pk, g_private_key_pem, keylen+1, NULL, 0);
    printf("%d %p\n", strlen(g_private_key_pem), g_private_key_pem);
    if (ret != 0) {
        ESP_LOGI(TAG, "pass private key error %d %x", keylen, -ret);
    } else {
        ESP_LOGI(TAG, "pass private key success"); 
        ret = mbedtls_pk_sign( &pk, MBEDTLS_MD_NONE,
         						digest, digest_len,
         						sign_data, sign_len,
         						mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) {
        	ESP_LOGI(TAG, "private key sign fail %d %x", ret, -ret);
            //char error_buf[100];
            //mbedtls_strerror(ret, error_buf, sizeof(error_buf));
            //ESP_LOGI(TAG, "rsa public decrypt error:%s", error_buf);
        }else{
        	ESP_LOGI(TAG, "private key sign ok %d %p", digest_len, sign_data);       	
    		ESP_LOG_BUFFER_HEXDUMP(TAG, digest, digest_len, ESP_LOG_INFO);
    		ESP_LOG_BUFFER_HEXDUMP(TAG, sign_data, *sign_len, ESP_LOG_INFO);              
        }
    }
    mbedtls_pk_free(&pk);

	ESP_LOG_BUFFER_HEXDUMP(TAG, sign_data, *sign_len, ESP_LOG_INFO); 
    return ret;
}

int rsa_private_data_sign(const unsigned char *private_key_pem, const unsigned char *msg_data,
                        size_t msg_len, unsigned char *sign_data, size_t *sign_len) 
{
    int ret;

    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info;
    uint8_t digest[32];
    int sign_size = 256;

    mbedtls_md_init(&ctx);
    info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_setup(&ctx, info, 0);
    //printf("md info setup, name: %s, digest size: %d\n", mbedtls_md_get_name(info), mbedtls_md_get_size(info));

    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, msg_data, msg_len);
    mbedtls_md_finish(&ctx, digest);

    mbedtls_md_free(&ctx);

    g_private_key_pem = private_key_pem;
    size_t digest_len = sizeof(digest);
    rsa_data_sign_only(digest, digest_len, sign_data, sign_len);
    ESP_LOG_BUFFER_HEXDUMP(TAG, sign_data, *sign_len, ESP_LOG_INFO); 
    return 0;    
}

void app_rsa_main(void) 
{
    int ret;
    const unsigned char *public_key_pem = g_id_rsa_public_key;
    const unsigned char *private_key_pem = g_id_rsa_private_key;
    const unsigned char *plaintext = NULL;
    size_t plaintext_len = 0;
    unsigned char *encrypted = NULL;;
    size_t encrypted_len = 256;
    unsigned char *decrypted = NULL;;
    size_t decrypted_len = 256;
    
    plaintext = (const unsigned char *) "Hello, RSA!";
    plaintext_len = strlen((const char *) plaintext);

    encrypted = (unsigned char *)malloc(256);
    encrypted_len = 256;

    ret = rsa_private_data_sign(private_key_pem, plaintext, plaintext_len, encrypted, &encrypted_len);
    if (ret != 0) {
        ESP_LOGI(TAG, "private key sign error ");
    } else {
    	ESP_LOGI(TAG, "private key sign ok %d %p", encrypted_len, encrypted);
        ESP_LOG_BUFFER_HEXDUMP(TAG, encrypted, encrypted_len, ESP_LOG_INFO);
    }

    decrypted = (unsigned char *)malloc(256);
    decrypted_len = 256;
	ret = rsa_public_sign_verify(public_key_pem, plaintext, plaintext_len, encrypted, encrypted_len);
	if (ret < 0) {
		ESP_LOGI(TAG, "Failed to verify data.");
	} else {
		//ESP_LOGI(TAG, "data: %s", decrypted);
	}

    // 清理Mbed TLS库
    mbedtls_platform_teardown(NULL);

    free(encrypted);
    free(decrypted);

    //mbedtls_ctr_drbg_free(&ctr_drbg);
    //mbedtls_entropy_free(&entropy);
}


int user_rsa_api_init(void)
{
    int ret = 0;

    g_public_key_pem = g_id_rsa_public_key;
    g_private_key_pem = g_id_rsa_private_key;
    printf("%d %d %p %p\n", strlen(g_public_key_pem), strlen(g_private_key_pem), g_public_key_pem, g_id_rsa_private_key);

    CRYPTO_Init();

    mbedtls_platform_setup(NULL);

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) {
        // Handle error
        ESP_LOGI(TAG, "random init error");
        ret = -1;
    }

    mbedtls_platform_teardown(NULL);

    app_rsa_main();

    return ret;
}