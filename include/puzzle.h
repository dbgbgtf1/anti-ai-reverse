#ifndef PUZZLE_H
#define PUZZLE_H

#include <stdbool.h>
#include <stdint.h>
#include <windows.h>
#include <wininet.h>
#include <winternl.h>

#define PUZZLE_URL_SEED 0x1fad

static void decode_url (WCHAR *url);
static bool parse_uuid (const char *body, size_t size, volatile char uuid[37]);

#endif
