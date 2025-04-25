#include <stdlib.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>    

//UTEST_INITIALIZER(start_server) {
void start_powershell_script(void) {
    system("start powershell -NoExit -File open_local_ssl_server.ps1");
}

int main() {
    mbedtls_net_context server_fd;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    const char *pers = "tls_client";
    int ret;

    start_powershell_script(); // Starte das PowerShell-Skript
    Sleep(2000); // Warte 2 Sekunden, um sicherzustellen, dass der Server gestartet ist

    // Initialisierung
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Zufallsgenerator seeden
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) {
        printf("mbedtls_ctr_drbg_seed fehlgeschlagen: %d\n", ret);
        goto exit;
    }

    // TLS 1.2 konfigurieren
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        printf("mbedtls_ssl_config_defaults fehlgeschlagen: %d\n", ret);
        goto exit;
    }
    mbedtls_ssl_conf_min_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE); // Selbstsigniertes Zertifikat

    // Verbindung zu localhost:5556
    if ((ret = mbedtls_net_connect(&server_fd, "localhost", "5556", MBEDTLS_NET_PROTO_TCP)) != 0) {
        printf("mbedtls_net_connect fehlgeschlagen: %d\n", ret);
        goto exit;
    }

    // SSL-Setup
    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        printf("mbedtls_ssl_setup fehlgeschlagen: %d\n", ret);
        goto exit;
    }
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    // Handshake
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            printf("mbedtls_ssl_handshake fehlgeschlagen: %d\n", ret);
            goto exit;
        }
    }
    printf("TLS 1.2 Handshake erfolgreich!\n");

    // Daten senden
    const char *msg = "Hallo vom mbedTLS-Client!";
    if ((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)msg, strlen(msg))) <= 0) {
        printf("mbedtls_ssl_write fehlgeschlagen: %d\n", ret);
        goto exit;
    }
    printf("Gesendet: %s\n", msg);

    // Daten empfangen
    unsigned char buf[1024];
    ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1);
    if (ret > 0) {
        buf[ret] = '\0';
        printf("Empfangen: %s\n", buf);
    }

exit:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}