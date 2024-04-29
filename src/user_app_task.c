
/* The config header is always included first. */
#include "iot_config.h"

/* Includes for library initialization. */
#include "iot_demo_runner.h"
#include "platform/iot_threads.h"
#include "types/iot_network_types.h"

#include "aws_demo.h"
#include "aws_demo_config.h"

/* Forward declaration of demo entry function to be renamed from #define in
 * aws_demo_config.h */
int DEMO_entryFUNCTION( bool awsIotMqttMode,
                        const char * pIdentifier,
                        void * pNetworkServerInfo,
                        void * pNetworkCredentialInfo,
                        const IotNetworkInterface_t * pNetworkInterface )
{
    int cnt = 0;

    extern void app_rsa_main(void);
    app_rsa_main();

    const char *argv[] = 
    {
        "tcp_server",
        "12345",
    };
    extern int tcp_server_main(int argc, const char *argv[]);
    return tcp_server_main(2, argv);

    while (1) {
        printf("%s:%d ... %d\n", __func__, __LINE__, ++cnt);
        vTaskDelay( pdMS_TO_TICKS( 1000) );
    }

    return 0;
}