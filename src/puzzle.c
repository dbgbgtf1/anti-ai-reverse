#include "../include/puzzle.h"
#include "../include/peb_helper.h"
#include <stdint.h>

#pragma clang section data = "payload_data"

static char uuid_key[] = "\"uuid\"";
static char flag[] = "DEFCON{";

/* Rolling XOR starts at PUZZLE_URL_SEED and advances by each decoded byte. */
static uint8_t encoded_url[] = { 0xc5, 0x61, 0xfd, 0x8d, 0x1e, 0xda,
                                 0x35, 0x66, 0x10, 0x94, 0x20, 0xb8,
                                 0x5a, 0xf3, 0x6d, 0x5f, 0xf0, 0x7c,
                                 0xe7, 0xc8, 0x63, 0xfe, 0x69, 0x0d };

#pragma clang section data = ""

#pragma clang section text = "code$A"

int
main (void)
{
  PEB *peb = (PEB *)__readgsqword (0x60);
  if (!peb || !peb->Ldr)
    return 1;

  dll_base bases;
  bases.user32 = 0;
  bases.ntdll = 0;
  bases.kernel32 = 0;
  bases.kernelbase = 0;
  bases.wininet = 0;
  get_dll_base (peb->Ldr, &bases);

  load_libraryw_fn load_library;
  free_library_fn free_library;
  openw_fn openw;
  openurlw_fn openurlw;
  queryinfow_fn queryinfow;
  read_file_fn read_file;
  close_handle_fn close_handle;

  // clang-format off
  if (get_func (bases.kernelbase, load_library_s, (uint64_t *)&load_library) != FUNC_DIRECT)
    return 1;

  if (get_func (bases.kernelbase, free_library_s, (uint64_t *)&free_library) != FUNC_DIRECT)
    return 1;

  HMODULE wininet_module = load_library (wininet);
  uint64_t wininet_base = (uint64_t)(uintptr_t)wininet_module;
  if (!wininet_base)
    return 1;

  if (get_func (wininet_base, open_s, (uint64_t *)&openw) != FUNC_DIRECT)
    goto unload;

  if (get_func (wininet_base, open_url_s, (uint64_t *)&openurlw) != FUNC_DIRECT)
    goto unload;

  if (get_func (wininet_base, query_info_s, (uint64_t *)&queryinfow) != FUNC_DIRECT)
    goto unload;

  if (get_func (wininet_base, read_file_s, (uint64_t *)&read_file) != FUNC_DIRECT)
    goto unload;

  if (get_func (wininet_base, close_handle_s, (uint64_t *)&close_handle) != FUNC_DIRECT)
    goto unload;
  // clang-format on

  WCHAR url[sizeof (encoded_url) + 1];
  char body[256];
  volatile char uuid[37];
  size_t used = 0;
  DWORD got = 0;
  DWORD status = 0;
  DWORD status_size = sizeof (status);
  int result = 1;
  HINTERNET request = NULL;

  decode_url (url);
  HINTERNET session
      = openw (agent_name, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
  if (!session)
    goto unload;

  request = openurlw (session, url, NULL, 0,
                      INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE
                          | INTERNET_FLAG_SECURE,
                      0);
  if (!request)
    goto done;

  if (!queryinfow (request, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                   &status, &status_size, NULL)
      || status != 200)
    goto done;

  do
    {
      if (used == sizeof (body))
        goto done;
      if (!read_file (request, body + used, (DWORD)(sizeof (body) - used),
                      &got))
        goto done;
      used += got;
    }
  while (got != 0);

  if (parse_uuid (body, used, uuid))
    result = 0;

  for (uint8_t i = 0; i < sizeof (flag) - 1; i++)
    body[i] = flag[i];
  for (uint8_t i = 0; i < sizeof (uuid) - 1; i++)
    body[i + sizeof (flag) - 1] = uuid[i];
  body[sizeof (flag) + sizeof (uuid) - 2] = '}';
  body[sizeof (flag) + sizeof (uuid) - 1] = '\0';

done:
  if (request)
    close_handle (request);
  close_handle (session);

unload:
  free_library (wininet_module);
  return ((uint64_t)&body) & 0xFFFFFFFFULL;
}

#pragma clang section text = "code$B"

static void
decode_url (WCHAR *url)
{
  uint16_t seed = PUZZLE_URL_SEED;
  for (size_t i = 0; i < sizeof encoded_url; ++i)
    {
      uint8_t decoded = encoded_url[i] ^ (uint8_t)seed;
      url[i] = (WCHAR)decoded;
      seed = (uint16_t)((seed + decoded) % 0x100);
    }
  url[sizeof (encoded_url)] = L'\0';
}

static bool
parse_uuid (const char *body, size_t size, volatile char uuid[37])
{
  for (size_t i = 0; i + sizeof (uuid_key) - 1 <= size; ++i)
    {
      size_t j = 0;
      while (j < sizeof (uuid_key) - 1 && body[i + j] == uuid_key[j])
        ++j;
      if (j != sizeof (uuid_key) - 1)
        continue;

      size_t at = i + j;
      while (at < size
             && (body[at] == ' ' || body[at] == '\t' || body[at] == '\r'
                 || body[at] == '\n'))
        ++at;
      if (at == size || body[at++] != ':')
        continue;
      while (at < size
             && (body[at] == ' ' || body[at] == '\t' || body[at] == '\r'
                 || body[at] == '\n'))
        ++at;
      if (at == size || body[at++] != '"' || size - at < 37)
        return false;

      for (size_t k = 0; k < 36; ++k)
        {
          char c = body[at + k];
          if (k == 8 || k == 13 || k == 18 || k == 23)
            {
              if (c != '-')
                return false;
            }
          else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
                     || (c >= 'A' && c <= 'F')))
            return false;
          uuid[k] = c;
        }
      if (body[at + 36] != '"')
        return false;
      uuid[36] = '\0';
      return true;
    }
  return false;
}

#pragma clang section text = ""
#include "peb_helper.c"
