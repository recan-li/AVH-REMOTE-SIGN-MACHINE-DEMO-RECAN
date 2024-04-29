<center><b>基于Arm虚拟硬件实现的简易远程固件签名机</b></center>

[toc]

----



# 1 写在前面

关于嵌入式开发的基本流程，我们都知道在常规的嵌入式开发中，由于需要物理开发板，所以在需要做一些开发调试时，往往需要在PC电脑上提前把应用程序使用交叉编译的手段把程序编译好，生成可在嵌入式芯片上运行的应用程序。然后通过相应的烧录工具，把准备好的应用程序烧录到芯片中，最后才能在嵌入式芯片中把应用程序的功能跑起来，以此来验证应用程序功能的正确性。

我们可以注意到，这一系列的过程，步骤繁杂，稍有某个环节不注意，可能就得不到预期的结果；同时，因为操作的流程多，大大降低了我们的开发和调试效率。

那么，有没有一种更高效的开发工具搭配新的开发方式，在保证调试运行结果正确的前提下，提升我们嵌入式开发的便捷性呢？

答案自然是有的，这就是我们本期实验手册要给大家介绍的一个非常强大的开发工具：**Arm 虚拟硬件平台 AVH（Arm Virtual Hardware）**。

&nbsp;

基于此，我们可以想到，借助Arm虚拟硬件平台，我们可以做一些非常实用有趣的工具，达到辅助我们日常开发的目的。比如，本期文章给大家介绍的 **远程固件签名机** 就是一个典型的例子，下文会对本案例做详细介绍。

&nbsp;

# 2 Arm虚拟硬件简介

**Arm 虚拟硬件（Arm Virtual Hardware, AVH）**提供了一个 Ubuntu Linux 镜像, 包括用于物联网、机器学习和嵌入式应用程序的 Arm 开发工具: 例如, Arm 编译器、FVP 模型和其他针对 Cortex-M 系列处理器的开发工具帮助开发者快速入门。Arm 虚拟硬件限时免费提供用于评估用途，例如，评估 **CI/CD、MLOps 和 DevOps 工作流** 中的自动化测试工作流等。

Arm虚拟硬件平台的主要特点包括：

- **虚拟化模型**：Arm虚拟硬件提供基于云的Arm处理器和系统的虚拟化模型，包括流行的IoT开发套件。这些模型不仅包括处理器，还涵盖了外围设备、传感器和其他板级组件。
- **软件开发便利性**：虚拟硬件使用成熟的、指令准确的、可扩展的建模引擎来替代物理硬件，使得开发者能够采用现代软件开发的最佳实践来开发IoT和端点AI应用程序。
- **可扩展性**：Arm虚拟硬件允许在云中轻松运行和扩展CI基础设施，可以在几秒钟内启动成千上万的虚拟板，快速实验和测试复杂的多设备配置。
- **加速开发**：开发者可以使用敏捷的软件开发实践，如CI/CD（DevOps）和MLOps工作流程，在Arm技术上快速开始开发和测试软件。

以下是Arm虚拟硬件的核心架构图：

![image-20240320173612445](http://share.recan-li.cn/bed/2024/04/28/bWtmKNAu4hpFLIY.png?my_wx_id=721317716)

<center>图1：Arm虚拟硬件的核心架构图</center>

&nbsp;

# 3 Demo项目说明

.**Demo项目主题**：**基于Arm虚拟硬件实现的简易远程固件签名机**

- 功能描述：利用 Arm 虚拟硬件平台的网络通讯及安全算法的计算能力，实现在一个局域网内或公域网中，对开发使用的固件bin文件或axf文件进行远程签名。
- 功能背景：在嵌入式团队开发中，为了基于对设备安全启动的考虑，一般都是需要对设备固件进行签名，然后才能得到已签名后的固件文件，将它放在 SecureBoot 或 Bootloader 中做固件的签名校验；只有通过了签名校验的固件才能成功加载运行起来，否则就报 **签名非法** 而终止加载运行。

&nbsp;

为了更好地实现上述功能需求，也方便在 Arm 虚拟硬件平台上做Demo级别的实现及功能验证，我们做了如下假设：

- 在网络通讯过程，暂不限定是局域网，可通过公网直接访问远程固件签名机提供的签名服务，如在真正的生产环境中，请注意签名权限的额外控制，或使用局域网通讯；
- 由于固件的bin文件可由axf文件导出生成，而在Arm虚拟硬件平台下，我们是直接加载axf文件进行模拟运行，所以这里签名的输入文件问axf文件；而在生产环境下使用，可以考虑对bin文件进行签名，实现思路是一致的；
- 由于在Arm虚拟硬件平台无法更好地实现SecureBoot的功能，即完成对已签名的axf文件的验签流程，这里借助一个外部脚本工具在达到模拟对axf文件进行验签控制的逻辑功能展示。

&nbsp;

更多的逻辑设计，可以参见下文的软件框架设计及核心代码实现。

&nbsp;

# 4 软件框架设计

整一个Demo项目的软件框架示意图，大体包含以下几个部分：

- 对axf文件发起签名请求的流程示意图
- 远程加密机对axf文件完成签名的流程示意图
- 对已签名的axf文件的验签流程示意图



## 4.1 请求签名流程

先看对axf文件的签名的流程示意图，如下图所示：

![image-20240430064458869](http://share.recan-li.cn/bed/2024/04/30/A7LGVyp4vtU1BEW.png?my_wx_id=721317716)

&nbsp;

## 4.2 远程执行签名流程

再看对远程签名机执行对axf文件的签名的流程示意图，如下图所示：

![image-20240430065639928](http://share.recan-li.cn/bed/2024/04/30/bcrMWOtLeBvYRoy.png?my_wx_id=721317716)

&nbsp;

## 4.3 签名验签流程

最后看对axf文件的签名验签的流程示意图，如下图所示：

![image-20240430064719941](http://share.recan-li.cn/bed/2024/04/30/3j8vEmXCWBzQD16.png?my_wx_id=721317716)

&nbsp;

# 5 核心代码实现

## 5.1 请求签名的脚本

如下所示即为脚本内容：

```python
import hashlib
import sys
import json
import socket
import os
import shutil
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

# 服务器地址和端口号
SERVER_HOST = '106.13.232.108'
SERVER_PORT = 12346

# public key
RSA_PUBLIC_KEY = '../rsa_key/id_rsa_public.pem'

# signed data hex length
SIGN_HEX_DATA_LEN = 512

def calculate_sha256(file_path, left_cnt):
	with open(file_path, "rb") as file:
		file_data = file.read()
		if left_cnt != 0:
			data_to_hash = file_data[:-left_cnt]
		else:
			data_to_hash = file_data

	# 计算数据的 SHA-256 散列值
	sha256 = hashlib.sha256()
	sha256.update(data_to_hash)
	hash_result = sha256.hexdigest().upper()

	return hash_result

def tcp_client_req(send_data):
	received_data = None
	client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	try:
		client_socket.connect((SERVER_HOST, SERVER_PORT))

		while True:            
			client_socket.sendall(send_data.encode())
			received_data = client_socket.recv(1024)
			if received_data is not None:            
				break
	
	except Exception as e:
		print("catch exception:", e)
		return None

	finally:
		client_socket.close()
		return received_data

def get_file_sign_from_remote(file_path):
	hash_value = calculate_sha256(file_path, 0)
	#print("sha256: ", hash_value)

	json_data = {}
	json_resp = None

	json_data['operation'] = 'rsa_sign_req'
	json_data['digest'] = hash_value
	json_str = json.dumps(json_data, separators=(',', ':'))
	print(json_str)

	received_data = tcp_client_req(json_str)
	if received_data is None:
		print("Get none resp data")
	#print("sign resp:", received_data.decode())
	json_resp = json.loads(received_data.decode())
	json_resp_str = json.dumps(json_resp, separators=(',', ':'))
	#print(json_resp['sign'])
	print(json_resp_str)
	
	return json_resp['sign']

def create_signed_file(file_path):
	print('Creating signature data of %s' % file_path)
	sign_data = get_file_sign_from_remote(file_path)
	dir_name = os.path.dirname(file_path)
	file_simple_name = os.path.splitext(os.path.basename(file_path))[0]
	file_suffix = os.path.splitext(file_path)[-1]
	signed_file_path = dir_name + '/' + file_simple_name + '-signed' + file_suffix

	#print(signed_file_path)
	shutil.copyfile(file_path, signed_file_path)
	with open(signed_file_path, "a") as file:
		file.write(sign_data)

	print('Creating signatured file %s' % signed_file_path)
	return signed_file_path

def verify_signed_file(signed_file_path):
	print('Checking signature data of %s' % signed_file_path)
	#hash_value_new = calculate_sha256(signed_file_path, SIGN_HEX_DATA_LEN)
	#print(hash_value_new)

	with open(signed_file_path, 'rb') as file:
		file.seek(-SIGN_HEX_DATA_LEN, 2)  # 从文件的末尾倒数第 512 个字节开始读取
		last_512_bytes = file.read()

	try:
		#print(last_512_bytes.decode())
		sign_data = bytes.fromhex(last_512_bytes.decode())
		#print(sign_data)
		#print(len(sign_data))
	except (ValueError, TypeError):
		print("Get Signature data failed.")
		return False

	with open(signed_file_path, "rb") as file:
		file_data = file.read()
		data_to_hash = file_data[:-SIGN_HEX_DATA_LEN]
	#print(data_to_hash)

	with open(RSA_PUBLIC_KEY, "r") as key_file:
		public_key = RSA.importKey(key_file.read())

	h = SHA256.new(data_to_hash)
	try:
		PKCS1_v1_5.new(public_key).verify(h, sign_data)
		print("Signature successfully.")
		return True
	except (ValueError, TypeError):
		print("Signature verification failed.")
		return False

def run_axf_file(axf_file):
	is_verify_ok = verify_signed_file(axf_file)
	if is_verify_ok:
		print("Verify ok, begin to run axf file ...")
		cmd = "/opt/VHT/bin/FVP_MPS2_Cortex-M7 --stat --simlimit 8000 -f ../AVH-CM7/vht_config.txt " + axf_file
		os.system(cmd)
	else:
		print("Verify fail, stop to run axf file ...")

def help():
	print("Usage: python " + sys.argv[0] + " [sign | verify | run] <file_path>")

if __name__ == "__main__":
	if len(sys.argv) < 3:
		help()
		sys.exit(1)

	if len(sys.argv) > 3:
		SERVER_PORT = int(sys.argv[3])

	operation = sys.argv[1]
	if operation == "sign":		
		file_path = sys.argv[2]
		signed_file_path = create_signed_file(file_path)
	elif operation == "verify":		
		signed_file_path = sys.argv[2]
		verify_signed_file(signed_file_path)
	elif operation == "run":
		axf_file = sys.argv[2]
		run_axf_file(axf_file)
	else:
		help()
		sys.exit(1)

	sys.exit(0)
```



## 5.2 远程签名机执行签名的代码示例

如下即为主要的签名处理流程：

这是处理客户端的请求签名示例代码：

```c
static int rsa_data_sign_handler(const char *msg_in, char *msg_out)
{
	uint8_t digest_bytes[32];
	uint8_t *sign_bytes = NULL;
	uint32_t sign_byets_len = 256;
	char * sign_hex_string = NULL;
	cJSON * in = NULL;
	cJSON * operation = NULL;
	cJSON * digest = NULL;

	in = cJSON_Parse(msg_in);
	operation = cJSON_GetObjectItem(in, "operation");
	digest = cJSON_GetObjectItem(in, "digest");

	sign_bytes = (unsigned char *)malloc(sign_byets_len);
	sign_hex_string = (char *)malloc(2048);

	//printf("%s %s\n", msg_in, digest->valuestring);
	hex_string_to_byte_array(digest->valuestring, digest_bytes);
	rsa_data_sign_only(digest_bytes, sizeof(digest_bytes), sign_bytes, &sign_byets_len);
	rsa_data_sign_verify_only(digest_bytes, sizeof(digest_bytes), sign_bytes, sign_byets_len);
	
	bcd_2_asc(sign_bytes, sign_byets_len, sign_hex_string);
	//printf("%s:%d %d %s\n", __func__, __LINE__, sign_byets_len, sign_hex_string);

	// 创建一个 cJSON 对象
    cJSON *root = cJSON_CreateObject();
    
    // 添加键值对到 cJSON 对象中
    cJSON_AddItemToObject(root, "operation", cJSON_CreateString("rsa_sign_resp"));
    cJSON_AddItemToObject(root, "sign", cJSON_CreateString(sign_hex_string));
    
    // 将 cJSON 对象转换为 JSON 字符串
    char *json_string = cJSON_Print(root);
    if (json_string) {
        //printf("JSON string: %s\n", json_string);
        memcpy(msg_out, json_string, strlen(json_string));
        free(json_string);  // 释放 cJSON_Print 返回的内存
    }
    
    // 释放 cJSON 对象
    cJSON_Delete(root);

	cJSON_Delete(in);

	free(sign_bytes);
	free(sign_hex_string);

	return 0;
}
```



如下即为RSA签名的核心代码展示：

```c
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
```



## 5.3 验签签名的脚本流程

本脚本与5.1的脚本复用一个，只不过走的流程case不一样，如下所示：

```python
def verify_signed_file(signed_file_path):
	print('Checking signature data of %s' % signed_file_path)
	#hash_value_new = calculate_sha256(signed_file_path, SIGN_HEX_DATA_LEN)
	#print(hash_value_new)

	with open(signed_file_path, 'rb') as file:
		file.seek(-SIGN_HEX_DATA_LEN, 2)  # 从文件的末尾倒数第 512 个字节开始读取
		last_512_bytes = file.read()

	try:
		#print(last_512_bytes.decode())
		sign_data = bytes.fromhex(last_512_bytes.decode())
		#print(sign_data)
		#print(len(sign_data))
	except (ValueError, TypeError):
		print("Get Signature data failed.")
		return False

	with open(signed_file_path, "rb") as file:
		file_data = file.read()
		data_to_hash = file_data[:-SIGN_HEX_DATA_LEN]
	#print(data_to_hash)

	with open(RSA_PUBLIC_KEY, "r") as key_file:
		public_key = RSA.importKey(key_file.read())

	h = SHA256.new(data_to_hash)
	try:
		PKCS1_v1_5.new(public_key).verify(h, sign_data)
		print("Signature successfully.")
		return True
	except (ValueError, TypeError):
		print("Signature verification failed.")
		return False

def run_axf_file(axf_file):
	is_verify_ok = verify_signed_file(axf_file)
	if is_verify_ok:
		print("Verify ok, begin to run axf file ...")
		cmd = "/opt/VHT/bin/FVP_MPS2_Cortex-M7 --stat --simlimit 8000 -f ../AVH-CM7/vht_config.txt " + axf_file
		os.system(cmd)
	else:
		print("Verify fail, stop to run axf file ...")
```





# 6 功能测试

## 6.1 请求签名的调试

使用脚本进行签名请求：

```sh
~/new/AVH-REMOTE-SIGN-MACHINE-DEMO-RECAN/tools$ python axf_sign_verify_tool.py sign ../axf/image-hello-world.axf 12346
Creating signature data of ../axf/image-hello-world.axf
{"operation":"rsa_sign_req","digest":"A25535F413E43337EA7BAF5F3353FB10FB6F45C78E8DFA5C23A042350D9F9CDC"}
{"operation":"rsa_sign_resp","sign":"4634FA6EC6683B08081C21299388C6FB5A7CF4628337E22994AFC861B79E32A66F7C293F5CDE7D637258FE29B8DC70EB8DB2508CC8FF9F9DE004D642ECA06731797F1998CB7A78F2E27051E5843005439D0D434B5D88AC331AC76F815A286E06DDE6CA5F74876686E725FEC00C4C06B40E9DE7A8E67541C60705E26A876F22C7EB7C3A91157DD8C982390114EAAC311C1F4CFFF720B2A84894299B0573BB04B5AB5D81FE9F3ADB88E8C624BD9FE705D649F8B7CEC1C7E49DDA0FF2C608B780358DE1156B590EE02D54B32D784B70C8A16032F4505D4945F13287F28614573A64E5D98DB6154E9A12EF22BB9EBB70AAA7142E3D8CC13D7F875106ECB7EFE04859"}
Creating signatured file ../axf/image-hello-world-signed.axf
```

成功拿到签名好的文件。

&nbsp;

## 6.2 远程签名机执行签名

初始化流程：

![image-20240430074221777](http://share.recan-li.cn/bed/2024/04/30/EYOow3szUDnqMXp.png?my_wx_id=721317716)

签名流程：

![image-20240430074406963](http://share.recan-li.cn/bed/2024/04/30/JcmrHPUGXg64fqK.png?my_wx_id=721317716)

## 6.3 签名验证的调试

验签成功的示例：

```sh
~/new/AVH-REMOTE-SIGN-MACHINE-DEMO-RECAN/tools$ python axf_sign_verify_tool.py run ../axf/image-hello-world-signed.axf
Checking signature data of ../axf/image-hello-world-signed.axf
Signature successfully.
Verify ok, begin to run axf file ...
telnetterminal2: Listening for serial connection on port 5003
telnetterminal1: Listening for serial connection on port 5004
telnetterminal0: Listening for serial connection on port 5005
[    0          3] [iot_thread] [INFO ][DEMO][2] ---------STARTING DEMO---------


[    1         11] [iot_thread] [INFO ][INIT][11] SDK successfully initialized.

[    2         19] [iot_thread] [INFO ][DEMO][19] Successfully initialized the demo. Network type for the demo: 4



Hello world @ Arm-AVH ...


[    3         33] [iot_thread] [INFO ][DEMO][33] memory_metrics::freertos_heap::before::bytes::140240

[    4         43] [iot_thread] [INFO ][DEMO][42] memory_metrics::freertos_heap::after::bytes::121384

[    5         55] [iot_thread] [INFO ][DEMO][55] memory_metrics::demo_task_stack::before::bytes::13100

[    6         65] [iot_thread] [INFO ][DEMO][65] memory_metrics::demo_task_stack::after::bytes::12816

[    7       1075] [iot_thread] [INFO ][DEMO][1075] Demo completed successfully.

[    8       1083] [iot_thread] [INFO ][INIT][1083] SDK cleanup done.

[    9       1090] [iot_thread] [INFO ][DEMO][1090] -------DEMO FINISHED-------

```



验签失败的示例：

```sh
~/new/AVH-REMOTE-SIGN-MACHINE-DEMO-RECAN/tools$ python axf_sign_verify_tool.py run ../axf/image-hello-world.axfChecking signature data of ../axf/image-hello-world.axf
Get Signature data failed.
Verify fail, stop to run axf file ...
```





# 7 更多思考

关于Arm虚拟硬件平台的几点优势，我想补充几点：

- Arm虚拟硬件平台给了非常便利的开发、编译、调试、运行验证的操作体验，无论是在开发阶段还是在生产阶段，都能给开发者及企业带来很大的便利；
- 相对于其他孤立的芯片开发平台，Arm虚拟硬件平台在成套的软件包上还是比较完毕的，比如RTOS相关的、网络相关的、安全相关的等等软件包，都可以通过快速配置得到比较好的复用，这一点在开发流程上，也得到了很大的改善；
- 借助Arm虚拟硬件的网络通讯平台，其具备公网通讯的能力，这一点可以在适当的功能扩展上做成很多基于网络通讯的应用工程，是一个值得期待的开发亮点。



当然，就当前的测试Demo来说，也还存在一些不同需要后续补充改进，比如：

- 如何在请求签名的通讯协议上加入签名的权限控制，而不是谁都可以发起签名请求，是一个将本Demo投入生产前需要重点考虑和设计的点；
- 执行签名的RSA私钥的保护，通过什么机制做好权限管理，也是实现远程加密机的重要安全保护举措，必须要考虑清楚；
- 在执行签名验证的环境，如何结合SecureBoot配合去做一些应用跳转，也是引入签名固件后的重大课题，也需要提前规划和设计。



整体来说，本Demo很好地完成了远程签名机功能演示级别的展示，也在一定程度上展示了Arm虚拟硬件平台的开发优势，但具体到真正的生产环境落地，还需要比较长的规划和设计要走，剩余的就交给开发者朋友吧。



# 8 参考资料

1. 如何在百度智能云服务上购买Arm虚拟硬件镜像云服务器？[https://armkeil.blob.core.windows.net/developer/Files/pdf/guide/arm-avh-best-practice-project-product-subscription-guide-cn.pdf](https://armkeil.blob.core.windows.net/developer/Files/pdf/guide/arm-avh-best-practice-project-product-subscription-guide-cn.pdf)
2. [Arm 虚拟硬件实践专题二：Arm 虚拟硬件 FVP 模型入门指南](https://mp.weixin.qq.com/s?search_click_id=1712312618188768077-1710148985019-9540351720&__biz=MjM5MzAyMzkwOA==&mid=2247492051&idx=3&sn=09c26a92f36d1cffac5e7aaa7af082c5&chksm=a7a5f32c2c78bf037ce2941d9b120fc3eacc2c04fb751e6ee816295fa78fc9f438eea24022c1&key=6d00be8b50bd1001282a1b10769245436d35b2b7f1d7388dad75e3942e139e82da0304b2afee259f355ded63b3b459da5e03313d9afeb43b419572b0100c14241001b4fe38ce878ebb130469cbe1b33fb88ea3c8ab64fdd7c9ea451c33a0165ae8b1a48be3d6ba9e38c6742b539e44542e724724f9f08ae094c7151cc30da7ae&ascene=0&uin=MTU4Nzc2MDgyMA%3D%3D&devicetype=Windows+10+x64&version=6309092b&lang=zh_CN&countrycode=CN&exportkey=n_ChQIAhIQlAJ2Pd5zEpboIPONbDjR8xLVAQIE97dBBAEAAAAAAOhJNg%2FoRrAAAAAOpnltbLcz9gKNyK89dVj0gPLt6OrTTO5KRqwBPFcRqaEgy2zQAzglJNxxlZNzG84gLZ8Y3r0CYSUqERia5Li9gI7bshocy9y365jOZLNM9oWlFkCZv3jC8JSvsdmEZC1h69uMYFHXXpkSEr%2B892yacDfBX%2BQYM2UUINKDX2oc2rmgYKxC%2FL8%2B79xrimbk7Ur7NuZRQCRC4eV8A6hITgdzFwVUons%2BQ0%2B0TaZ7rCc3B0wJy1xHnRObwPTakfX6Yg%3D%3D&acctmode=0&pass_ticket=eTshn%2FK4hptsgQk2ZPmkE%2FAt8EQa%2BhihOLr%2B8dv9F65vGsUzAhcQoersYGZBH6B2NjrH2ejKxz0bPyoHPO6YXA%3D%3D&wx_header=1)
3. Arm官网对Arm虚拟硬件的介绍 [https://www.arm.com/products/development-tools/simulation/virtual-hardware](https://www.arm.com/products/development-tools/simulation/virtual-hardware)
4. Arm虚拟硬件解决方案详解 [https://arm-software.github.io/AVH/main/overview/html/index.html](https://arm-software.github.io/AVH/main/overview/html/index.html)
5. 本Demo的示例代码仓库地址：[recan-li/AVH-REMOTE-SIGN-MACHINE-DEMO-RECAN (github.com)](https://github.com/recan-li/AVH-REMOTE-SIGN-MACHINE-DEMO-RECAN)