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
 * @file mbedtls.h
 * @brief Schnittstelle für die mbedTLS-Verschlüsselungsschicht.
 *
 * Diese Datei enthält die Funktionsprototypen und Strukturen für
 * die Implementierung von AES-GCM-Verschlüsselung mit mbedTLS.
 */
#ifndef __mbedtls_H
#define __mbedtls_H

/* ==================================================================
 * INCLUDES
 * ================================================================== */
#include "mbedtls_swan/mbedtls_config.h"
#include "mbedtls/entropy.h"

/* ==================================================================
 * DEFINES
 * ================================================================== */

typedef struct {
    const char *name;
    const char *port;
    const char *ca_cert; // CA Zertifikat
    size_t ca_cert_len;
} ServerConfig;

/* ==================================================================
 * FUNCTION PROTOTYPES
 * ================================================================== */

// Für TLS 1.2 & TLS 1.3

/**
 * @brief Initialisiert die mbedTLS-Speicherverwaltung.
 *
 * Statischer Speicherpuffer für mbedTLS Speicherverwaltung
 *
 * Dieser Speicher wird von mbedTLS für dynamische Allokationen genutzt,
 * um Heap-Fragmentierung und Speicherprobleme durch malloc()/free() zu vermeiden.
 *
 * Die Größe von 16 KB wurde basierend auf folgenden Faktoren gewählt:
 * - AES-GCM benötigt zusätzlichen Speicher für Nonce, Tag und GCM-Operationen.
 * - TLS 1.2 benötigt je nach Cipher Suite zwischen 4 KB und 12 KB Speicher.
 * - Statische Speicherallokation verhindert Fragmentierung und verbessert
 *   die Vorhersagbarkeit der Speicherverwaltung.
 *
 * Falls Speicherprobleme auftreten:
 * - Kleinere Systeme (z. B. STM32 mit < 64 KB RAM): auf 8 KB reduzieren.
 * - TLS 1.3 oder mehrere TLS-Sessions: auf 24-32 KB erhöhen.
 *
 * Siehe auch: `mbedtls_memory_buffer_alloc_status()` zur Speicherüberprüfung.
 */
void alloc_mbedtls_memory(void);

/**
 * @brief Führt einen TLS-Handshake und HTTP-GET-Test mit mbedTLS durch.
 */
void startTLSClientTask(ServerConfig server_conf);

void test_mbedtls(void);

/**
 * @brief Übergeben der Hardware-basierte Zufallszahlengenerierung des STM32L4 an mbedTLS.
 * @param ctx Unbenutzter Parameter (NULL).
 * @param output Puffer für die Zufallszahlen.
 * @param len Anzahl der zu generierenden Bytes.
 * @param olen Tatsächlich generierte Bytes.
 * @return 0 bei Erfolg, MBEDTLS_ERR_ENTROPY_SOURCE_FAILED bei Fehler.
 */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen);

/****************************** DEBUG *******************************/
#ifdef DEBUG

void print_available_ciphersuites(void);

#endif /* DEBUG */

/****************************** DEBUG ENDE **************************/

#endif /*__mbedtls_H */

