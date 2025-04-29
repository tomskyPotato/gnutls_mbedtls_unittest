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
 * Copyright Weptech elektronik GmbH Germany
 */

/**
 ******************************************************************************
 * @file      net_sockets.h
 * @author    Thomas Lommel (tomsky0721@gmail.com)
 * @version   1.0
 * @date      01.04.2025
 *
 * @brief
 * Deklarationen für die mbedTLS-Netzwerkschnittstelle auf Basis eines
 * AT-kommandogesteuerten UART-Modems.
 *
 * @details
 * Diese Datei stellt die Funktionsprototypen für den Zugriff auf ein
 * AT-Modem (z. B. Quectel BC66) zur Verfügung, das als Transportmedium
 * für mbedTLS verwendet wird. Die Implementierung kapselt die Interaktion
 * über AT-Befehle und bietet eine net_sockets-kompatible API.
 ******************************************************************************
 */

#ifndef MBEDTLS_SWAN_NET_SOCKETS_H
#define MBEDTLS_SWAN_NET_SOCKETS_H

#include <stddef.h>
#include <stdint.h>

/* -------------------------------------------------------------------------- */
/*                                  Konstanten                                */
/* -------------------------------------------------------------------------- */

#define MBEDTLS_ERR_NET_INVALID_CONTEXT    -0x0045  /**< Ungültiger oder nicht initialisierter Kontext */
#define MBEDTLS_NET_PROTO_TCP              0        /**< Nur TCP wird unterstützt */

/* -------------------------------------------------------------------------- */
/*                                   Typedefs                                 */
/* -------------------------------------------------------------------------- */

/**
 * @brief Kontextstruktur für die Netzwerkschnittstelle von mbedTLS.
 *        Wird bei dieser Implementierung nicht verwendet, aber für API-Kompatibilität benötigt.
 */
typedef struct {
    int fd; /**< Platzhalterfeld (nicht verwendet) */
} mbedtls_net_context;

/* -------------------------------------------------------------------------- */
/*                             Öffentliche Funktionen                         */
/* -------------------------------------------------------------------------- */

/**
 * @brief Initialisiert den Socket-Kontext.
 *
 * Setzt das fd-Feld auf -1. Bei dieser Implementierung wird das Feld nicht
 * weiterverwendet.
 *
 * @param ctx Zeiger auf den zu initialisierenden Socket-Kontext
 */
void mbedtls_net_init(mbedtls_net_context *ctx);

/**
 * @brief Öffnet eine TCP-Verbindung zu einem entfernten Host über AT-Befehle.
 *
 * Diese Funktion baut eine Verbindung über ein UART-basiertes AT-Modem auf.
 *
 * @param ctx   Zeiger auf Socket-Kontext (nicht ausgewertet)
 * @param host  Zielhost (IP oder DNS-Name)
 * @param port  Zielport als Nullterminierter String
 * @param proto Verbindungsprotokoll (nur MBEDTLS_NET_PROTO_TCP zulässig)
 *
 * @return 0 bei Erfolg, -1 bei Fehler
 */
int mbedtls_net_connect(mbedtls_net_context *ctx, const char *host, const char *port, int proto);

/**
 * @brief Sendet Daten über das Modem.
 *
 * Die Daten werden in einen temporären Puffer kopiert und über einen
 * AT-Befehl gesendet. Bei erfolgreichem Versand wird die Länge der Daten
 * zurückgegeben.
 *
 * @param ctx Zeiger auf Socket-Kontext (nicht ausgewertet)
 * @param buf Zeiger auf zu sendende Daten
 * @param len Länge der Daten
 *
 * @return Anzahl gesendeter Bytes oder -1 bei Fehler
 */
int mbedtls_net_send(void *ctx, const unsigned char *buf, size_t len);

/**
 * @brief Empfängt Daten vom Modem.
 *
 * Es wird zunächst versucht, Daten aus dem internen FIFO zu lesen. Wenn
 * nicht genug vorhanden ist, wird über AT-Befehle ein neuer Empfang
 * ausgelöst. Die gelesenen Bytes werden im Puffer `buf` abgelegt.
 *
 * @param ctx Zeiger auf Socket-Kontext (nicht ausgewertet)
 * @param buf Zeiger auf Puffer für empfangene Daten
 * @param len Maximale Anzahl zu empfangender Bytes
 *
 * @return Anzahl gelesener Bytes oder MBEDTLS_ERR_SSL_WANT_READ
 */
int mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len);

/**
 * @brief Initialisiert den internen FIFO-Puffer für empfangene Daten.
 *
 * Muss vor dem ersten Empfang über `mbedtls_net_recv()` aufgerufen werden.
 */
void tls_fifo_init(void);

#endif /* MBEDTLS_SWAN_NET_SOCKETS_H */
