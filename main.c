

/**
 * Copyright (c) 2024 Gregory C Herlein
 * Derived from sample code at https://www.iopress.info/index.php/books/master-the-raspberry-pi-pico-in-c-wifi-with-lwip-mbedtls/9-programs/73-picocprogramswifi?showall=1
 * SPDX-License-Identifier: BSD-3-Clause
 */
/**
 * Copyright (c) 2022 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <string.h>

#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "dhcpserver.h"
#include "dnsserver.h"

typedef struct TCP_SERVER_T_
{
    struct tcp_pcb *server_pcb;
    bool complete;
    ip_addr_t gw;
    async_context_t *context;
} TCP_SERVER_T;

typedef struct TCP_CONNECT_STATE_T_
{
    struct tcp_pcb *pcb;
    int sent_len;
    char headers[128];
    char result[256];
    int header_len;
    int result_len;
    ip_addr_t *gw;
} TCP_CONNECT_STATE_T;

#define UDP_PORT 4444
#define BEACON_MSG_LEN_MAX 127
#define BEACON_TARGET "255.255.255.255"
#define BEACON_INTERVAL_MS 250

void run_udp_beacon()
{
    struct udp_pcb *pcb = udp_new();

    ip_addr_t addr;
    ipaddr_aton(BEACON_TARGET, &addr);

    int counter = 0;
    while (true)
    {
        int led_state = !cyw43_arch_gpio_get(CYW43_WL_GPIO_LED_PIN);
        cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, led_state);

        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, BEACON_MSG_LEN_MAX + 1, PBUF_RAM);
        char *req = (char *)p->payload;
        memset(req, 0, BEACON_MSG_LEN_MAX + 1);
        snprintf(req, BEACON_MSG_LEN_MAX, "%d\n", counter);
        err_t er = udp_sendto(pcb, p, &addr, UDP_PORT);
        pbuf_free(p);
        if (er != ERR_OK)
        {
            printf("Failed to send UDP packet! error=%d", er);
        }
        else
        {
            printf("Sent packet %d\n", counter);
            counter++;
        }

        // Note in practice for this simple UDP transmitter,
        // the end result for both background and poll is the same

#if PICO_CYW43_ARCH_POLL
        // if you are using pico_cyw43_arch_poll, then you must poll periodically from your
        // main loop (not from a timer) to check for Wi-Fi driver or lwIP work that needs to be done.
        cyw43_arch_poll();
        sleep_ms(BEACON_INTERVAL_MS);
#else
        // if you are not using pico_cyw43_arch_poll, then WiFI driver and lwIP work
        // is done via interrupt in the background. This sleep is just an example of some (blocking)
        // work you might be doing.
        sleep_ms(BEACON_INTERVAL_MS);
#endif
    }
}

int main()
{
    // workaround for a hardware debug problem
    // https://forums.raspberrypi.com/viewtopic.php?t=363914
    // also in openocd you need to us -c "set USE_CORE 0"  before rp2040.cfg is loaded per https://github.com/raspberrypi/debugprobe/issues/45
    timer_hw->dbgpause = 0;
    sleep_ms(150);

    stdio_init_all();

    TCP_SERVER_T *state = calloc(1, sizeof(TCP_SERVER_T));
    if (!state)
    {
        printf("failed to allocate state\n");
        return 1;
    }

    if (cyw43_arch_init())
    {
        printf("failed to initialise\n");
        return 1;
    }

    const char *ap_name = "picow_test";
    const char *password = "";

    cyw43_arch_enable_ap_mode(ap_name, password, CYW43_AUTH_OPEN);

    printf("AP mode enabled\n");

    ip4_addr_t mask;
    // Start the dhcp server
    dhcp_server_t dhcp_server;
    dhcp_server_init(&dhcp_server, &state->gw, &mask);

    // Start the dns server
    dns_server_t dns_server;
    dns_server_init(&dns_server, &state->gw);

    printf("IP: %s\n",
           ip4addr_ntoa(netif_ip_addr4(netif_default)));
    printf("Mask: %s\n",
           ip4addr_ntoa(netif_ip_netmask4(netif_default)));
    printf("Gateway: %s\n",
           ip4addr_ntoa(netif_ip_gw4(netif_default)));
    printf("Host Name: %s\n",
           netif_get_hostname(netif_default));

    while (true)
    {
        run_udp_beacon();
    }

    cyw43_arch_deinit();
    return 0;
}
