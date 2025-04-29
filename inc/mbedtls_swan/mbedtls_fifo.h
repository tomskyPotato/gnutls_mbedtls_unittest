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
 * @file      fifo.h
 * @author    Thomas Lommel
 * @version   1.0
 * @date      01.04.2025
 *
 * @brief
 * Header für eine einfache, nicht blockierende Ringpuffer-Implementierung.
 *
 * @details
 * Diese FIFO-Implementierung erlaubt sequentielles Schreiben und Lesen
 * von Bytes in einem zirkulären Puffer. Sie wird in Kommunikationsstacks
 * eingesetzt, bei denen ein asynchroner Empfang von Daten (z. B. über UART)
 * gepuffert und später verarbeitet werden muss.
 *
 * Die Funktionen sind nicht thread-safe.
 ******************************************************************************
 */

#ifndef MBEDTLS_SWAN_FIFO_H
#define MBEDTLS_SWAN_FIFO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* -------------------------------------------------------------------------- */
/*                                  Datentypen                                */
/* -------------------------------------------------------------------------- */

/**
 * @brief Struktur eines zirkulären Byte-FIFOs.
 */
typedef struct {
    uint8_t *buffer;  /**< Zeiger auf den Puffer */
    size_t   size;    /**< Größe des Puffers */
    size_t   head;    /**< Schreibposition */
    size_t   tail;    /**< Leseposition */
} fifo_t;

/* -------------------------------------------------------------------------- */
/*                             Öffentliche Funktionen                         */
/* -------------------------------------------------------------------------- */

/**
 * @brief Initialisiert den FIFO mit einem extern bereitgestellten Puffer.
 *
 * @param fifo   Zeiger auf die FIFO-Struktur
 * @param buffer Zeiger auf den Byte-Puffer
 * @param size   Größe des Puffers
 *
 * @return true bei Erfolg, false bei ungültigen Parametern
 */
bool fifo_init(fifo_t *fifo, uint8_t *buffer, size_t size);

/**
 * @brief Gibt die Anzahl der aktuell gespeicherten Bytes im FIFO zurück.
 *
 * @param fifo Zeiger auf die FIFO-Struktur
 *
 * @return Anzahl der verfügbaren Bytes zum Lesen
 */
size_t fifo_available(const fifo_t *fifo);

/**
 * @brief Gibt die noch freie Kapazität im FIFO zurück.
 *
 * @param fifo Zeiger auf die FIFO-Struktur
 *
 * @return Anzahl der noch schreibbaren Bytes
 */
size_t fifo_space(const fifo_t *fifo);

/**
 * @brief Liest Daten aus dem FIFO in einen Zielpuffer.
 *
 * @param fifo Zeiger auf die FIFO-Struktur
 * @param dest Zielpuffer
 * @param len  Maximale Anzahl zu lesender Bytes
 *
 * @return Tatsächlich gelesene Bytes
 */
size_t fifo_read(fifo_t *fifo, uint8_t *dest, size_t len);

/**
 * @brief Schreibt Daten aus einem Quellpuffer in den FIFO.
 *
 * @param fifo Zeiger auf die FIFO-Struktur
 * @param src  Quellpuffer
 * @param len  Anzahl der zu schreibenden Bytes
 *
 * @return Tatsächlich geschriebene Bytes
 */
size_t fifo_write(fifo_t *fifo, const uint8_t *src, size_t len);

/**
 * @brief Setzt den FIFO zurück, ohne den Pufferinhalt zu verändern.
 *
 * @param fifo Zeiger auf die FIFO-Struktur
 */
void fifo_clear(fifo_t *fifo);

#endif /* MBEDTLS_SWAN_FIFO_H */
