/*
 * __          __        _            _
 * \ \        / /       | |          | |
 *  \ \  /\  / /__ _ __ | |_ ___  ___| |__
 *   \ \/  \/ / _ \ '_ \| __/ _ \/ __| '_ \
 *    \  /\  /  __/ |_) | ||  __/ (__| | | |
 *     \/  \/ \___| .__/ \__\___|\___|_| |_|
 *                | |
 *                |_|
 *       _      _    _                   _ _       _____           _     _    _
 *      | |    | |  | |                 (_) |     / ____|         | |   | |  | |
 *   ___| | ___| | _| |_ _ __ ___  _ __  _| | __ | |  __ _ __ ___ | |__ | |__| |
 *  / _ \ |/ _ \ |/ / __| '__/ _ \| '_ \| | |/ / | | |_ | '_ ` _ \| '_ \|  __  |
 * |  __/ |  __/   <| |_| | | (_) | | | | |   <  | |__| | | | | | | |_) | |  | |
 *  \___|_|\___|_|\_\\__|_|  \___/|_| |_|_|_|\_\  \_____|_| |_| |_|_.__/|_|  |_|
 *
 *
 * Copyright Weptech elektronik GmbH Germany
 *
 */
/*
 ******************************************************************************
 * @file      net_sockets.c
 * @author    Thomas Lommel (tomsky0721@gmail.com)
 * @version   1.0
 * @date      01.04.2025
 *
 * @brief
 * Adapter für die Integration von mbedTLS mit einem AT-basierten Modem
 * (z. B. Quectel BC66) über eine serielle UART-Verbindung.
 *
 * @details
 * Diese Implementierung stellt die net_sockets-Schnittstelle von mbedTLS bereit
 * und leitet die üblichen Netzwerkoperationen (connect, send, recv) auf
 * AT-Kommandos um. Die Kommunikation erfolgt über ein serielles Modem,
 * das TCP-Verbindungen auf Kommandoebene aufbaut und verwaltet.
 *
 * Empfangene Daten werden über einen internen FIFO gepuffert, um asynchrone
 * Antwortzeiten des Modems abzufangen und der mbedTLS-API eine
 * socket-ähnliche Schnittstelle bereitzustellen.
 *
 ******************************************************************************/

/* -------------------------------------------------------------------------- */
/*                            Header Files			                          */
/* -------------------------------------------------------------------------- */
#include "mbedtls_swan/net_sockets.h"
#include "at_commands.h"
#include "cellular_module.h"
#include "project.h"
#include "bc66.h"
#include "mbedtls_swan/mbedtls_fifo.h"
#include "ssl.h"


/* -------------------------------------------------------------------------- */
/*                            Variablen				                          */
/* -------------------------------------------------------------------------- */

static uint8_t mbedtls_recive_buffer[BC66_MAX_STRING_LEN];
static uint8_t fifo_storage[2 * BC66_MAX_STRING_LEN]; // doppelte Größe für Sicherheit
static fifo_t tls_fifo;

/* -------------------------------------------------------------------------- */
/*                            Öffentliche Funktionen                          */
/* -------------------------------------------------------------------------- */

void mbedtls_net_init(mbedtls_net_context *ctx)
{
    ctx->fd = -1;  // wird nicht verwendet
}

int mbedtls_net_connect(mbedtls_net_context *ctx, const char *host, const char *port, int proto)
{
	(void)ctx;
	(void)proto;
    uint8_t pktP[64];

    const char *cmdTemplate = "AT+QIOPEN=1,0,\"TCP\",\"%s\",%s,0,1";
    _sprintf_((char *)pktP, cmdTemplate, host, port);

    if (AT_SendCmd((const char *)pktP, NULL, 0, 10, 5000) != AT_RSP_TYPE_OK) {
        DBG_PRINT("Fehler: TCP-Verbindung konnte nicht geöffnet werden!\r\n");
        return -1;
    } else {
        ctx = 0;  // (eigentlich: ctx->fd = 0;)
    }

    /*
    if (AT_SendCmd("AT+QISTATE?", "+QISTATE: 0,4", 0, 10, 5000) != AT_RSP_TYPE_OK) {
        DBG_PRINT("Fehler: TCP-Verbindung nicht erfolgreich!\r\n");
        return -1;
    }
    */

    return 0;
}

int mbedtls_net_send(void *ctx, const unsigned char *buf, size_t len)
{
	(void)ctx;
    if (CM_SendData(0, buf, len, CM_SENDFLAG_ENABLE_RAI_AND_EXPECT_ONE_DL_PKT) == STATUS_SUCCESS) {
        DBG_PRINT("Swan2-R: Sende (%lu Bytes).\r\n", len);
    } else {
        DBG_PRINT("Swan2-R: Senden gescheitert.\r\n");
    }
    return (int)len;
}

void tls_fifo_init(void)
{
    fifo_init(&tls_fifo, fifo_storage, sizeof(fifo_storage));
}

int mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len)
{
	(void)ctx;
    Status_t status;
    size_t readLen = 0;

    //DBG_PRINT("Swan2-R: Aktueller FIFO-Stand: %lu Bytes\r\n", (unsigned long)fifo_available(&tls_fifo));

    if (!buf || len == 0) {
        DBG_PRINT("Swan2-R: recv mit ungültigem Buffer\r\n");
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }

    // Wenn nicht genug Daten im FIFO sind, hole mehr vom Modem
    if (fifo_available(&tls_fifo) < len) {
        status = CM_RecieveData(0, (char*)mbedtls_recive_buffer, &readLen, BC66_MAX_STRING_LEN, 5000);
        if (status == STATUS_SUCCESS && readLen > 0) {
            //DBG_PRINT("Swan2-R: Neue Daten vom Modem empfangen: %lu Bytes\r\n", (unsigned long)readLen);
            fifo_write(&tls_fifo, mbedtls_recive_buffer, readLen);
            //DBG_PRINT("Swan2-R: FIFO nach Write: %lu Bytes\r\n", (unsigned long)fifo_available(&tls_fifo));

            //DBG_PRINT("Swan2-R: Empfangenes Datenpaket (hex): ");
            for (size_t i = 0; i < readLen; i++) {
                //DBG_PRINT("%02X ", mbedtls_recive_buffer[i]);
            }
            //DBG_PRINT("\r\n");

        } else {
            DBG_PRINT("Swan2-R: MBEDTLS_ERR_SSL_WANT_READ\r\n");
            return MBEDTLS_ERR_SSL_WANT_READ;
        }
    }

    // Jetzt aus dem FIFO lesen
    size_t actuallyRead = fifo_read(&tls_fifo, buf, len);
    //DBG_PRINT("Swan2-R: TLS gibt %lu Bytes aus FIFO an mbedTLS weiter\r\n", (unsigned long)actuallyRead);
    //DBG_PRINT("Swan2-R: FIFO nach Read: %lu Bytes\r\n", (unsigned long)fifo_available(&tls_fifo));

    return (int)actuallyRead;
}
