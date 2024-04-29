#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

#include <errno.h>
#if 0
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#define CFG_SIGNAL_ENABLE 			0
#define CFG_PTHREAD_ENABLE 			0
#define CFG_AWS_IOT_SOCKET_ENABLE 	1
#define CFG_RSA_SIGN_ENABLE 		1

#if (CFG_SIGNAL_ENABLE)
#include <signal.h>
#endif

#if (CFG_PTHREAD_ENABLE)
#include <pthread.h>
#else
#include "iot_config.h"
#include "platform/iot_platform_types_freertos.h"
#include "platform/iot_threads.h"
#include "types/iot_platform_types.h"
#include "cmsis_os2.h"
#endif

#if (CFG_AWS_IOT_SOCKET_ENABLE)
#include "iot_socket.h"
#define AF_INET						IOT_SOCKET_AF_INET
#define SOCK_STREAM 				IOT_SOCKET_SOCK_STREAM
//#define 
#define socket(af, type, protocol) 	iotSocketCreate(af, type, protocol)
#define listen(fd, backlog) 		iotSocketListen (fd, backlog)
#define read(fd, buf, len) 			iotSocketRecv(fd, buf, len)
#define write(fd, buf, len) 		iotSocketSend(fd, buf, len)
#define close(fd) 					iotSocketClose(fd)
#define INET_ADDRSTRLEN 			128
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif
 
#define MAX_CLINET_NUM 10 /** 最大客户端连接数，可根据实际情况增减 */
 
/** 使用hexdump格式打印数据的利器 */
static void hexdump(const char *title, const void *data, unsigned int len)
{
    char str[160], octet[10];
    int ofs, i, k, d;
    const unsigned char *buf = (const unsigned char *)data;
    const char dimm[] = "+------------------------------------------------------------------------------+";
 
    printf("%s (%d bytes)\n", title, len);
    printf("%s\r\n", dimm);
    printf("| Offset  : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F   0123456789ABCDEF |\r\n");
    printf("%s\r\n", dimm);
 
    for (ofs = 0; ofs < (int)len; ofs += 16) {
        d = snprintf( str, sizeof(str), "| %08x: ", ofs );
        for (i = 0; i < 16; i++) {
            if ((i + ofs) < (int)len)
                snprintf( octet, sizeof(octet), "%02x ", buf[ofs + i] );
            else
                snprintf( octet, sizeof(octet), "   " );
 
            d += snprintf( &str[d], sizeof(str) - d, "%s", octet );
        }
        d += snprintf( &str[d], sizeof(str) - d, "  " );
        k = d;
 
        for (i = 0; i < 16; i++) {
            if ((i + ofs) < (int)len)
                str[k++] = (0x20 <= (buf[ofs + i]) &&  (buf[ofs + i]) <= 0x7E) ? buf[ofs + i] : '.';
            else
                str[k++] = ' ';
        }
 
        str[k] = '\0';
        printf("%s |\r\n", str);
    }
 
    printf("%s\r\n", dimm);
}
 
/** 获取客户端的ip和端口信息 */
static int get_clinet_ip_port(int sock, char *ip_str, int len, int *port)
{
#if (CFG_AWS_IOT_SOCKET_ENABLE)
	uint16_t cli_port = 0;
	uint8_t cli_ip[4] = {0};
	uint32_t cli_ip_len = sizeof(cli_ip);
	iotSocketGetPeerName (sock, (uint8_t *)cli_ip, (uint32_t *)&cli_ip_len, (uint16_t *)&cli_port);
	snprintf(ip_str, len, "%d.%d.%d.%d", cli_ip[0], cli_ip[1], cli_ip[2], cli_ip[3]);
	*port = cli_port;
#else
    struct sockaddr_in sa;
    int sa_len;
	
    sa_len = sizeof(sa);
    if(!getpeername(sock, (struct sockaddr *)&sa, &sa_len)) {
        *port = ntohs(sa.sin_port);
        snprintf(ip_str, len, "%s", inet_ntoa(sa.sin_addr));
    }
#endif
    return 0;
}

#if 0
//execute shell command
static int shexec(int sock_fd, const char *cmd)
{
	int rv;
    char tmp[1024];
	FILE *pp;
	char out[1024];
	int offset = 0;
	
	printf("=================================================\n");
    printf("shexec, cmd: %s\n", cmd);

    pp = popen(cmd, "r");
    if(!pp) {
        printf("error, cannot popen cmd: %s\n", cmd);
        return -1;
    }
    
    while(fgets(tmp, sizeof(tmp), pp) != NULL) {
		//rv = write(sock_fd, tmp, strlen(tmp));
		memcpy(&out[offset], tmp, strlen(tmp));
		offset += strlen(tmp);
		//printf("write rv: %d\r\n", rv);
		printf("%s", tmp);
    }
	
	rv = write(sock_fd, out, offset);

    rv = pclose(pp);
    printf("ifexited: %d\n", WIFEXITED(rv));
    if (WIFEXITED(rv))
    {
		char msg[128] = {0};
        printf("subprocess exited, exit code: %d\n", WEXITSTATUS(rv));
		if (!WEXITSTATUS(rv)) {
			snprintf(msg, sizeof(msg), "Final result: OK\r\n");
		} else {
			snprintf(msg, sizeof(msg), "Final result: FAIL\r\n");
		}
		write(sock_fd, msg, strlen(msg));
    }
	
	printf("=================================================\n");

    return rv;
}
#endif

#if (CFG_RSA_SIGN_ENABLE)

// 将单个十六进制字符转换为对应的整数值
unsigned char hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
 	return 0; // 处理非法字符，默认0
}

// 将十六进制字符串转换为字节数组
void hex_string_to_byte_array(const char* hex_string, unsigned char* byte_array) 
{
    size_t len = strlen(hex_string);
    size_t i;
    for (i = 0; i < len; i += 2) {
        byte_array[i/2] = (hex_char_to_int(hex_string[i]) << 4) + hex_char_to_int(hex_string[i+1]);
    }
}

//将二进制源串分解成双倍长度可读的16进制串, 如 0x12AB-->"12AB"
void bcd_2_asc(uint8_t *psIHex, int32_t iHexLen, char *psOAsc)
{
    static const char szMapTable[17] = {"0123456789ABCDEF"};
    int32_t   iCnt,index;
    unsigned char  ChTemp;
 
    for(iCnt = 0; iCnt < iHexLen; iCnt++)
    {
        ChTemp = (unsigned char)psIHex[iCnt];
        index = (ChTemp / 16) & 0x0F;
        psOAsc[2*iCnt]   = szMapTable[index];
        ChTemp = (unsigned char) psIHex[iCnt];
        index = ChTemp & 0x0F;
        psOAsc[2*iCnt + 1] = szMapTable[index];
    }
}

extern int rsa_data_sign_only(const unsigned char *digest, size_t digest_len, unsigned char *sign_data, size_t *sign_len);
extern int rsa_data_sign_verify_only(const unsigned char *digest, size_t digest_len, unsigned char *sign_data, size_t sign_len);
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
#endif
 
/** 服务器端处理客户端请求数据的线程入口函数 */
static void client_deal_func(void* arg)
{
    int client_sock = *(int *)arg;    

#if 0 //(0 && CFG_AWS_IOT_SOCKET_ENABLE)
    int timeout = 0;
    uint32_t len = 0;
    int ret;
    int non_block = 0;
    ret = iotSocketGetOpt(client_sock, IOT_SOCKET_IO_FIONBIO, &non_block, &len);
    printf("non_block: %d %d %d\n", ret, non_block, len);
    non_block = 1;
    ret = iotSocketSetOpt (client_sock, IOT_SOCKET_IO_FIONBIO, &non_block, sizeof(non_block));
    printf("non_block: %d %d\n", ret, non_block);
    ret = iotSocketGetOpt(client_sock, IOT_SOCKET_IO_FIONBIO, &non_block, &len);
    printf("non_block: %d %d %d\n", ret, non_block, len);
    ret = iotSocketGetOpt(client_sock, IOT_SOCKET_SO_RCVTIMEO, &timeout, &len);
    printf("time: %d %d %d\n", ret, timeout, len);
    timeout = 10 * 10;
    ret = iotSocketSetOpt (client_sock, IOT_SOCKET_SO_RCVTIMEO, &timeout, sizeof(timeout));
    printf("time: %d %d\n", ret, timeout);
    ret = iotSocketGetOpt(client_sock, IOT_SOCKET_SO_RCVTIMEO, &timeout, &len);
    printf("time: %d %d %d\n", ret, timeout, len);
#endif

    while(1) {  
        char buf[1024] = {"hello"};
        int ret = 5;
#if 1	
        memset(buf,'\0',sizeof(buf));
        ret = read(client_sock,buf,sizeof(buf)); /* 读取客户端发送的请求数据 */
        if (ret <= 0) {
        	printf("read fail(%d) %d\n", client_sock, ret);
            break; /* 接收出错，跳出循环 */
        }
#endif
 
        hexdump("server recv:", buf, ret);
#if 1
#if (CFG_RSA_SIGN_ENABLE)
        ret = rsa_data_sign_handler(buf, buf);
        ret = strlen(buf);
#endif

        ret = write(client_sock, buf, ret); /* 将收到的客户端请求数据发送回客户端，实现echo的功能 */
        if( ret < 0) {
            break; /* 发送出错，跳出循环 */
        }
#else
		{
			const char *input_cmd = (const char *)buf;
			shexec(client_sock, input_cmd);
			break;
		}
#endif
    }
	
    close(client_sock);

#if !(CFG_PTHREAD_ENABLE)
	osThreadExit();
#endif
}

static void test_main(void *arg)
{
	int cnt = 0;
	int flag = *(int *)arg;

	while (1) {
		printf("%s:%d ... (%d)%d\n", __func__, __LINE__, flag, ++cnt);
		vTaskDelay(1000);
		if (cnt > 20) {
			printf("%s:%d ... (%d)%d exit\n", __func__, __LINE__, flag, ++cnt);
			break;
		}
	}

#if !(CFG_PTHREAD_ENABLE)
	osThreadExit();
#endif
}
 
/** 服务器主函数入口，接受命令参数输入，指定服务器监听的端口号 */
#if 0
int main(int argc, char **argv)
#else
int tcp_server_main(int argc, const char *argv[])
#endif
{
    int ret;
    int ser_port = 0;
    int ser_sock = -1;
    int client_sock = -1;
#if !(CFG_AWS_IOT_SOCKET_ENABLE)	
    struct sockaddr_in server_socket;
    struct sockaddr_in socket_in;
#endif
#if (CFG_PTHREAD_ENABLE)
    pthread_t thread_id; 
#endif 
    int val = 1;
	
#if (CFG_SIGNAL_ENABLE)
	signal(SIGPIPE,SIG_IGN);
#endif

#if 0
	{
		static const osThreadAttr_t test_attr = {
		  .stack_size = 4096U
		};
		int flag = 1;
        extern osThreadId_t osThreadNew (osThreadFunc_t func, void *argument, const osThreadAttr_t *attr);
        osThreadNew(test_main, (int *)&flag, &test_attr);
        flag++;
        osThreadNew(test_main, (int *)&flag, &test_attr);
        flag++;
        osThreadNew(test_main, (int *)&flag, &test_attr);
	}
#endif
	
    /* 命令行参数的简单判断和help提示 */
    if(argc != 2) {
        printf("usage: %s [port]\n", argv[0]);
        ret = -1;
        goto exit_entry;
    }
	
    /* 读取命令行输入的服务器监听的端口 */
    ser_port = atoi(argv[1]);
    if (ser_port <=0 || ser_port >= 65536) {
        printf("server port error: %d\n", ser_port);
        ret = -2;
        goto exit_entry;
    }
	
    /* 创建socket套接字 */
    ser_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(ser_sock < 0) {
        perror("socket error");
        return -3;
    }
		
#if !(CFG_AWS_IOT_SOCKET_ENABLE)
    /* 设置socket属性，使得服务器使用的端口，释放后，别的进程立即可重复使用该端口 */
    ret = setsockopt(ser_sock, SOL_SOCKET,SO_REUSEADDR, (void *)&val, sizeof(val));
    if(ret == -1) {
        perror("setsockopt");
        return -4;
    }
#endif

#if (CFG_AWS_IOT_SOCKET_ENABLE)
    uint8_t ip[4] = { 0U, 0U, 0U, 0U };
    if((ret = iotSocketBind (ser_sock, (const uint8_t *)ip, sizeof(ip), ser_port)) < 0)
#else
    bzero(&server_socket, sizeof(server_socket));
    server_socket.sin_family = AF_INET;
    server_socket.sin_addr.s_addr = htonl(INADDR_ANY); //表示本机的任意ip地址都处于监听
    server_socket.sin_port = htons(ser_port);
	
    /* 绑定服务器信息 */
    if(bind(ser_sock, (struct sockaddr*)&server_socket, sizeof(struct sockaddr_in)) < 0)
#endif
    {
    	printf("bind ret: %d %d %d\n", ret, ser_sock, ser_port);
        ret = -5;
        goto exit_entry;
    }
	
    /* 设置服务器监听客户端的最大数目 */
    if(listen(ser_sock, MAX_CLINET_NUM) < 0) { 
        perror("listen error");
        ret = -6;
        goto exit_entry;
    }
	
    printf("TCP server create success, accepting clients @ port %d ...\n", ser_port);

    for(;;) { /* 循环等待客户端的连接 */
        char buf_ip[INET_ADDRSTRLEN];
        printf("accepting ...\n");     
#if (CFG_AWS_IOT_SOCKET_ENABLE)
        uint32_t ip_len = sizeof(buf_ip);
        uint16_t port = 0;
        client_sock = iotSocketAccept (ser_sock, (uint8_t *)buf_ip, &ip_len, &port);
#else
        socklen_t len = 0;
        client_sock = accept(ser_sock, (struct sockaddr*)&socket_in, &len);
#endif
        if(client_sock < 0) {
            perror("accept error");
            ret = -7;
            continue;
        } else {
        	printf("accepted fd %d ...\n", client_sock);
        }		
        
        {
            char client_ip[128];
            int client_port;
            get_clinet_ip_port(client_sock, client_ip, sizeof(client_ip), &client_port);
            /* 打印客户端的ip和端口信息 */
            printf("client connected [ip: %s, port :%d]\n", client_ip, client_port);
        }

#if (CFG_PTHREAD_ENABLE)		
        /* 使用多线程的方式处理客户端的请求，每接收一个客户端连接，启动一个线程处理对应的数据 */
        pthread_create(&thread_id, NULL, (void *)client_deal_func, (void *)&client_sock);  
        pthread_detach(thread_id);
#else
#if 0
        if( xTaskCreate( client_deal_func,
                         "tcp_server",
                         ( configSTACK_DEPTH_TYPE ) 2048,
                         (void *)&client_sock,
                         6,
                         NULL ) != 1)
#else
        static const osThreadAttr_t cli_attr = {
		  .stack_size = 8192
		};
        extern osThreadId_t osThreadNew (osThreadFunc_t func, void *argument, const osThreadAttr_t *attr);
        printf("creating thread ...\n");
        osThreadNew(client_deal_func, (int *)&client_sock, &cli_attr);
        printf("create thread done\n");
#endif
        {
        	//printf("create thread fail\n");
        }
        //vTaskDelay(10);
#endif
    }
	
exit_entry:
    if (ser_sock >= 0) {
        close(ser_sock); /* 程序退出前，释放socket资源 */
    }

    return 0;
}