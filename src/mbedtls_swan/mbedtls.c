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

/**
 * @file    mbedtls.c
 * @author  Thomas Lommel (tomsky0721@gmail.com)
 * @brief   TLS-Testclient und AES-GCM-Debugfunktionen mit mbedTLS
 * @version 1.0
 * @date    01.04.2025
 *
 * @details
 * Dieses Modul initialisiert mbedTLS für Embedded TLS-Kommunikation.
 * TLS-Handshake sowie Send/Receive erfolgen über Wrapper.
 */

// C-Standardbibliotheken (Allgemeine Funktionen)
#include <stdio.h>                      // Für snprintf (Formatierung von Zeichenketten)
#include <string.h>                    	// Für memcpy, strlen (Speicheroperationen)
#include <stdlib.h>                    	// Für atoi, malloc, NULL
#include <string.h>

// mbedTLS-Bibliotheken (Kryptografie)
#include "mbedtls/aes.h"              	// AES-Verschlüsselung
#include "mbedtls/gcm.h"              	// GCM-Modus für AES
#include "mbedtls/entropy.h"          	// Entropiequelle für sichere Zufallszahlen
#include "mbedtls/error.h"            	// Fehlertexte für mbedtls_strerror()
#include "mbedtls/memory_buffer_alloc.h" // Statische Speicherverwaltung
#include "mbedtls/ctr_drbg.h"         	// Deterministischer Zufallszahlengenerator
#include "mbedtls/platform.h"         	// Plattformfunktionen wie malloc, printf
#include "mbedtls/ssl.h"              	// TLS-Kontext und Handshake
#include "mbedtls/x509_crt.h"         	// Zertifikate
#include "mbedtls/debug.h"            	// Debug-Ausgabe
#include "mbedtls/certs.h"            	// Beispiel-Zertifikate (z. B. Root-CA)
#include "mbedtls/cipher.h"

// SWAN2 Includes
#include "mbedtls_swan/net_sockets.h" 	// SWAN-spezifische net_sockets Wrapper
#include "mbedtls_swan/mbedtls.h"     	// Projektabhängige TLS-Konfiguration
#include "mbedtls_swan/mbedtls_fifo.h"

#include "main.h"                     	// Globale Hardware-Handles (z. B. hrng)
#include "trace.h"                    	// DBG_PRINT, TRACE_STR
#include "project.h"                  	// Projektkonfiguration
#include "at_commands.h"              	// AT-Befehle
#include "bc66.h"                     	// Quectel-spezifische Funktionen
#include "cellular_module.h"          	// CM_OpenSocket, CM_SendData etc.
#include "status.h"                   	// STATUS_SUCCESS, Status_t

// Handle für den Zufallszahlengenerator in HW des STM32
extern RNG_HandleTypeDef    	hrng;

// mbed TLS Elemente
// Müssen statisch im RAM bleiben zur Laufzeit; alles andere führt zu Problemen
static mbedtls_ssl_context     	ssl;
static mbedtls_ssl_config      	conf;
static mbedtls_entropy_context 	entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_x509_crt        	ca_cert;
static mbedtls_net_context 		server_fd;

// Gestattet mbedtls selbständig speicher zu allocieren.
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#define MEMORY_HEAP_SIZE      20000
uint8_t alloc_buf[MEMORY_HEAP_SIZE];
#endif

#define DEBUG_LEVEL 1	// 4 ist höchstes Level, das gibt am meisten aus

// Cipherliste: Der Server fängt oben an zu schauen welche er unterstützt,
// daher fangen wir mit den sparsamen an und staffeln sinnvoll:
//
// Zuerst ECDHE-ECDSA (kleiner, sparsamer, moderner)
// Danach Fallback auf RSA (breiter unterstützt)
// Innerhalb beider Gruppen: erst CBC (stromsparend), dann GCM (schneller, mehr RAM)
const int ciphersuites[] = {
    //----------------------------------------------------------------------
    // ECDHE-ECDSA Ciphers (kleiner, sparsamer, moderner)
    //----------------------------------------------------------------------

    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,  // Energiespar-Modus
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,  // Performance-Modus
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,  // Heavy Mode
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,  // Max Security

    //----------------------------------------------------------------------
    // RSA Ciphers (Fallback, breiter unterstützt)
    //----------------------------------------------------------------------

    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,          // Fallback: Energiespar-Modus mit RSA
    MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,          // Fallback: Performance-Modus mit RSA
    MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,          // Fallback: Heavy Mode mit RSA
    MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,          // Fallback: Max Security mit RSA

    0
};

/* ==================================================================
 * FUNCTION IMPLEMENTATIONS
 * ================================================================== */

// Verbindet die Hardware Random Number Generator mit mbedTls
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    (void)data;

    for (size_t i = 0; i < len; i += sizeof(uint32_t)) {
        uint32_t r;
        if (HAL_RNG_GenerateRandomNumber(&hrng, &r) != HAL_OK)
            return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;

        size_t copy_len = (len - i < sizeof(uint32_t)) ? len - i : sizeof(uint32_t);
        memcpy(output + i, &r, copy_len);
    }

    *olen = len;
    return 0;
}

// Übergibt weptech Debug Print Ausgabe Format an mbedtls
static void my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
	(void) ctx;   // suppress unused warning
	((void) level);
	DBG_PRINT("\r\n%s:%04d: %s\r\n", file, line, str);
	DBG_UART_FLUSH_TX_FIFO();
}

// Testfunktion initialisiert mbedtls und sendet und empfängt einen HTTPS String
#include <mbedtls_swan/test_zertifikate/ca_rsa_weptech_iot_de.h>
#include <mbedtls_swan/test_zertifikate/ca_ecdsa_weptech_iot_de.h>
#include <mbedtls_swan/test_zertifikate/ca_ecdsa_mqtt_broker.h>
//#include <mbedtls_swan/test_zertifikate/ca_rsa_lets_encrypt_x1_root_ca.h>
void test_mbedtls(void){
//*************** TEST HTTP
#define NO_SERVER_VERIFICATION
	ServerConfig httpConf;
	httpConf.name = "weptech-iot.de";
	httpConf.port = "5690"; //TODO Port kann durchgehend als int verwendet werden
	httpConf.ca_cert = ca_crt;
	httpConf.ca_cert_len = ca_crt_len;
	// Für OTA starte TLS Connection mit Heimat Server: weptech-iot.de
	startTLSClientTask(httpConf);

	send_http_over_tls();

    recv_http_over_tls();
}

// Nutzt die mbedtls send Funktion um einen HTTP-String über die TLS Verbindung zu senden
void send_http_over_tls(void){
	int ret = 1;
	const char *http_request = "GET / HTTP/1.1\r\nHost: weptech-iot.de\r\nConnection: close\r\n\r\n";
	ret = mbedtls_ssl_write(&ssl, (const unsigned char *) http_request, strlen(http_request));
	if (ret < 0) {
	    DBG_PRINT("Fehler beim Senden der HTTP-Anfrage: -0x%x\r\n", -ret);
	} else {
	    DBG_PRINT("HTTP-Anfrage gesendet (%d Bytes)\r\n", ret);
	}

}

// Nutzt die mbedtls send Funktion um einen HTTP-String über die TLS Verbindung zu empfangen
void recv_http_over_tls(void){
	unsigned char response[1024];
	memset(response, 0, sizeof(response));
	int ret = 1;

	ret = mbedtls_ssl_read(&ssl, response, sizeof(response) - 1);
	if (ret <= 0) {
	    DBG_PRINT("Fehler beim Empfang: -0x%x\r\n", -ret);
	} else {
	    DBG_PRINT("HTTP-Antwort (%d Bytes):\r\n%s\r\n", ret, response);
	}

}

// Initialisierungsfunktion baut den sicheren TLS Kanal auf. Mit dem Kontext ssl kann dann über mbedtls gesendet und empfangen werden
void startTLSClientTask(ServerConfig server_conf)
{
	DBG_PRINT("\r\n======================================================================\r\n");
	DBG_PRINT("Starte TLS-HTTP Test\r\n\r\n");
	DBG_UART_FLUSH_TX_FIFO();

	int ret = 1;

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
	// Initialisiere statischen Speicher für mbedTLS (spart Heap)
	mbedtls_memory_buffer_alloc_init(alloc_buf, sizeof(alloc_buf));
#endif

#if defined(MBEDTLS_DEBUG_C)
	// Setze Debug-Ausgabestufe (0 = aus, 4 = maximal)
	mbedtls_debug_set_threshold(DEBUG_LEVEL);
	mbedtls_ssl_conf_dbg(&conf, my_debug, NULL);
#endif

	DBG_PRINT("mbedtls: Initialisiere TLS-Komponenten und Zufallsquelle mit Hardware-RNG...\r\n");
	DBG_UART_FLUSH_TX_FIFO();

	// Initialisiere TLS-Komponenten
	const char *alpn_list[] = { "http/1.1", NULL };
	mbedtls_net_init(&server_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_ssl_conf_alpn_protocols(&conf, alpn_list);
	mbedtls_x509_crt_init(&ca_cert);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	// Erzwinge die Verwendung von TLS 1.2
    mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);

	// Initialisiere Zufallsquelle mit Hardware-RNG
	const char *pers = "weptech-iot.de";	// Personalisierungsstring sorgt für zusätzliche Randomisierung der Zufallszahl
	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
	                             (const unsigned char *)pers, strlen(pers));
	if (ret != 0) {
		DBG_PRINT(" failed: Fehler! mbedtls_ctr_drbg_seed returned %d\r\n", ret);
		goto exit;
	} else {
		// Übergebe Zufallsquell an Konfigurations Kontext
		mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
		DBG_PRINT(" OK\r\n");
	}

	// Lade Zertifikat
	DBG_PRINT("mbedtls: Lade CA-Zertifikat...");
	DBG_UART_FLUSH_TX_FIFO();

	// Zertifikat einlesen, führt bei falscher Formatierung zu fehlern. Fehlercode ist zu finden unter x509.h  * \name X509 Error codes
	ret = mbedtls_x509_crt_parse(&ca_cert, (const unsigned char *) server_conf.ca_cert, server_conf.ca_cert_len);
	if (ret < 0) {
		DBG_PRINT(" failed: Fehler! mbedtls_x509_crt_parse returned -0x%x\r\n", (unsigned int)-ret);
		goto exit;
	} else {
		// Übergebe Zertifikat an Konfigurations Kontext
		mbedtls_ssl_conf_ca_chain(&conf, &ca_cert, NULL);
		DBG_PRINT(" OK\r\n");
	}

	// Konfiguriere TLS-Client mit Standardparametern
	DBG_PRINT("mbedtls: Konfiguriere TLS-Client mit Standardparametern...");
	DBG_UART_FLUSH_TX_FIFO();

	ret = mbedtls_ssl_config_defaults(&conf,
	                                  MBEDTLS_SSL_IS_CLIENT,
	                                  MBEDTLS_SSL_TRANSPORT_STREAM,
	                                  MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		DBG_PRINT(" failed: Fehler! mbedtls_ssl_config_defaults returned %d\r\n", ret);
		goto exit;
	} else {
		DBG_PRINT(" OK\r\n");
	}

	// Authentifizierungsmodus konfigurieren
	DBG_PRINT("mbedtls: Setze Authentifizierungsmodus...");
	DBG_UART_FLUSH_TX_FIFO();

	// Setze Authentifizierungsmodus
#ifdef NO_SERVER_VERIFICATION
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
#else
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
#endif

	// Cipher Liste übergeben
	mbedtls_ssl_conf_ciphersuites(&conf, ciphersuites);

	// TLS-Struktur initialisieren
	ret = mbedtls_ssl_setup(&ssl, &conf);
	if (ret != 0) {
		DBG_PRINT(" failed: Fehler! mbedtls_ssl_setup returned %d\r\n", ret);
		goto exit;
	} else {
		DBG_PRINT(" OK\r\n");
	}

	// Hostname für SNI setzen
	DBG_PRINT("mbedtls: Setze Hostname für TLS...");
	DBG_UART_FLUSH_TX_FIFO();

	ret = mbedtls_ssl_set_hostname(&ssl, server_conf.name);
	if (ret != 0) {
		DBG_PRINT(" failed: Fehler! mbedtls_ssl_set_hostname returned %d\r\n", ret);
		goto exit;
	} else {
		DBG_PRINT(" OK\r\n");
	}

	// Registriere Sende-/Empfangs-Funktionen
	DBG_PRINT("mbedtls: Registriere I/O-Funktionen...");
	DBG_UART_FLUSH_TX_FIFO();

	mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
	DBG_PRINT(" OK\r\n");
	DBG_UART_FLUSH_TX_FIFO();

	// TCP-Verbindung herstellen
	DBG_PRINT("mbedtls: Starte TCP-Verbindung zu %s:%s...", server_conf.name, server_conf.port);
	DBG_UART_FLUSH_TX_FIFO();

	uint16_t server_port = (uint16_t)atoi(server_conf.port);
	const char *server_name = server_conf.name;
	const unsigned int socket_id = 0;

	while (1) {
		if (CM_OpenSocket(socket_id, server_name, server_port, 0, CM_SOCKET_TYPE_TCP, CM_SOCKET_MODE_DIRECT) == STATUS_SUCCESS) {
			DBG_PRINT(" OK\r\n");
			break;
		} else {
			DBG_PRINT(" failed: Verbindung fehlgeschlagen. Neuer Versuch...\r\n");
			osDelay(1000);
		}
	}

	// TLS-Handshake durchführen
	DBG_PRINT("\r\nmbedtls: Führe TLS-Handshake durch...");
	DBG_UART_FLUSH_TX_FIFO();

	// Initialisiert den fifo der für mbedtls send und recv funktionen gebraucht wird.
	tls_fifo_init();

	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			char error_buf[100];
			mbedtls_strerror(ret, error_buf, sizeof(error_buf));
			DBG_PRINT(" failed: Handshake fehlgeschlagen! Fehler: %s\r\n", error_buf);
			goto exit;
		} else {
			DBG_PRINT(" OK\r\n");
		}
	}

#ifndef NO_SERVER_VERIFICATION
    /*
     * 5. Verify the server certificate
     */
	DBG_PRINT("\r\n");
	DBG_PRINT("mbedtls: Verifying peer X.509 certificate...");
	uint32_t ret2;
    /* In real life, we probably want to bail out when ret != 0 */
    if((ret2 = mbedtls_ssl_get_verify_result(&ssl)) != 0)
    {
      char vrfy_buf[512];
      DBG_PRINT(" failed\r\n");
      mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", ret2);
      DBG_PRINT("%s\r\n", vrfy_buf);
      goto exit;
    } else {
    	DBG_PRINT(" OK\r\n");
    }
#endif

	DBG_UART_FLUSH_TX_FIFO();
	DBG_PRINT("\r\n");
	DBG_PRINT("mbedtls: Handshake erfolgreich\r\n");
	DBG_PRINT("\r\n======================================================================\r\n");
	DBG_PRINT("Ende TLS-HTTP Test\r\n\r\n");
	DBG_UART_FLUSH_TX_FIFO();
	return;

exit:
	DBG_PRINT("mbedtls: Unerwarteter Abbruch!\r\n\r\n");
	DBG_UART_FLUSH_TX_FIFO();
}


/****************************** DEBUG *******************************/
#ifdef DEBUG

/*----------------------------------------------------------------------------*/
void print_available_ciphersuites(void)
{
    const int *ciphersuite_id = mbedtls_ssl_list_ciphersuites();

    printf("\r\n");
    printf("Aktivierte mbedTLS Ciphersuites:\r\n");

    while (*ciphersuite_id != 0)
    {
        const char *cipher_name = mbedtls_ssl_get_ciphersuite_name(*ciphersuite_id);

        if (cipher_name != NULL)
        {
            printf(" - %s\r\n", cipher_name);
        }

        ciphersuite_id++;
    }
    printf("\r\n");
}

#endif

/****************************** DEBUG ENDE **************************/
