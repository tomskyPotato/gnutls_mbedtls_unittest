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
 * @file      mbedtls_fifo.c
 * @author    Thomas Lommel
 * @version   1.0
 * @date      01.04.2025
 *
 * @brief
 * Implementierung eines zirkulären FIFO-Puffers (Ringpuffer) zur Byteweise-
 * Datenpufferung. Eingesetzt für UART-/Modem-Kommunikation mit mbedTLS.
 ******************************************************************************
 */

#include "mbedtls_swan/mbedtls_fifo.h"
#include <string.h>

/* -------------------------------------------------------------------------- */
/*                            Öffentliche Funktionen                          */
/* -------------------------------------------------------------------------- */

/**
 * @brief Initialisiert einen FIFO-Puffer.
 *
 * @param fifo   Zeiger auf die FIFO-Struktur
 * @param buffer Zeiger auf externen Puffer
 * @param size   Größe des Puffers
 *
 * @return true bei Erfolg, false bei ungültigen Parametern
 */
bool fifo_init(fifo_t *fifo, uint8_t *buffer, size_t size)
{
    if (!fifo || !buffer || size == 0) {
        return false;
    }

    fifo->buffer = buffer;
    fifo->size   = size;
    fifo->head   = 0;
    fifo->tail   = 0;
    return true;
}

/**
 * @brief Gibt die Anzahl der aktuell gespeicherten Bytes zurück.
 *
 * @param fifo Zeiger auf FIFO
 *
 * @return Verfügbare Bytes
 */
size_t fifo_available(const fifo_t *fifo)
{
    return (fifo->head - fifo->tail) % fifo->size;
}

/**
 * @brief Gibt die verbleibende freie Kapazität zurück.
 *
 * @param fifo Zeiger auf FIFO
 *
 * @return Freier Speicherplatz in Bytes
 */
size_t fifo_space(const fifo_t *fifo)
{
    return fifo->size - fifo_available(fifo) - 1;
}

/**
 * @brief Liest Daten aus dem FIFO in den Zielpuffer.
 *
 * @param fifo Zeiger auf FIFO
 * @param dest Zielpuffer
 * @param len  Maximale Anzahl Bytes zum Lesen
 *
 * @return Tatsächlich gelesene Bytes
 */
size_t fifo_read(fifo_t *fifo, uint8_t *dest, size_t len)
{
    size_t count = 0;

    while (count < len && fifo_available(fifo) > 0) {
        dest[count++] = fifo->buffer[fifo->tail];
        fifo->tail = (fifo->tail + 1) % fifo->size;
    }

    return count;
}

/**
 * @brief Schreibt Daten aus einem Quellpuffer in den FIFO.
 *
 * @param fifo Zeiger auf FIFO
 * @param src  Quellpuffer
 * @param len  Anzahl der zu schreibenden Bytes
 *
 * @return Tatsächlich geschriebene Bytes
 */
size_t fifo_write(fifo_t *fifo, const uint8_t *src, size_t len)
{
    size_t count = 0;

    while (count < len && fifo_space(fifo) > 0) {
        fifo->buffer[fifo->head] = src[count++];
        fifo->head = (fifo->head + 1) % fifo->size;
    }

    return count;
}

/**
 * @brief Setzt den FIFO-Zustand zurück, ohne den Puffer zu löschen.
 *
 * @param fifo Zeiger auf FIFO
 */
void fifo_clear(fifo_t *fifo)
{
    fifo->head = 0;
    fifo->tail = 0;
}
