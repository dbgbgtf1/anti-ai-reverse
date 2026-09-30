#include "../include/peb_helper.h"
#include <stdbool.h>
#include <stdint.h>

#pragma clang section text = "code$C"

static bool
my_memicmp (void *dst, void *src, size_t size)
{
  uint8_t *left = (uint8_t *)dst;
  uint8_t *right = (uint8_t *)src;
  for (size_t i = 0; i < size; ++i)
    {
      uint8_t a = left[i];
      uint8_t b = right[i];
      if (a >= 'a' && a <= 'z')
        a -= 0x20;
      if (b >= 'a' && b <= 'z')
        b -= 0x20;
      if (a != b)
        return true;
    }
  return false;
}

static bool
my_memcmp (void *dst, void *src, size_t size)
{
  uint8_t *left = (uint8_t *)dst;
  uint8_t *right = (uint8_t *)src;
  for (size_t i = 0; i < size; ++i)
    if (left[i] != right[i])
      return true;
  return false;
}

static uint64_t
my_strlen (void *dst)
{
  uint8_t *text = (uint8_t *)dst;
  uint64_t length = 0;
  while (text[length])
    ++length;
  return length;
}

static uint32_t
search_func (uint64_t dll_base, char *func_name,
             PIMAGE_EXPORT_DIRECTORY export_table)
{
  uint32_t name_count = export_table->NumberOfNames;
  uint32_t *names = (uint32_t *)(dll_base + export_table->AddressOfNames);
  uint32_t *functions
      = (uint32_t *)(dll_base + export_table->AddressOfFunctions);
  uint16_t *ordinals
      = (uint16_t *)(dll_base + export_table->AddressOfNameOrdinals);
  size_t func_name_len = (size_t)my_strlen (func_name);

  for (uint32_t i = 0; i < name_count; ++i)
    {
      char *name = (char *)(dll_base + names[i]);
      if (!my_memcmp (name, func_name, func_name_len + 1))
        return functions[ordinals[i]];
    }
  return 0;
}

static func_result
get_func (uint64_t dll_base, char *func_name, uint64_t *result)
{
  if (!dll_base)
    return NOT_FOUND;
  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dll_base;
  PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dll_base + dos->e_lfanew);
  IMAGE_DATA_DIRECTORY export_dir
      = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (!export_dir.VirtualAddress || !export_dir.Size)
    return NOT_FOUND;

  PIMAGE_EXPORT_DIRECTORY exports
      = (PIMAGE_EXPORT_DIRECTORY)(dll_base + export_dir.VirtualAddress);
  uint32_t rva = search_func (dll_base, func_name, exports);
  if (!rva)
    return NOT_FOUND;
  if (rva >= export_dir.VirtualAddress
      && rva - export_dir.VirtualAddress < export_dir.Size)
    return FUNC_FORWARDER;

  *result = dll_base + rva;
  return FUNC_DIRECT;
}

#define IF_MEMCMP_DLL_NAME(dll_name)                                          \
  if (dll->Length == (sizeof (dll_name) - sizeof (L""))                       \
      && !my_memicmp (dll->Buffer, (void *)dll_name, dll->Length))            \
    bases->dll_name = (uint64_t)data->DllBase;

static void
get_dll_base (struct _PEB_LDR_DATA *ldr, dll_base *bases)
{
  LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
  LIST_ENTRY *link = head->Flink;
  while (link != head)
    {
      my_LDR_DATA_TABLE_ENTRY *data = CONTAINING_RECORD (
          link, my_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

      UNICODE_STRING *dll = &data->BaseDllName;

      // clang-format off
      IF_MEMCMP_DLL_NAME (kernel32)
      else IF_MEMCMP_DLL_NAME (kernelbase)
      else IF_MEMCMP_DLL_NAME (wininet)

      if (bases->user32 && bases->kernel32 && bases->ntdll && bases->kernelbase) break;
      // clang-format on

      link = link->Flink;
    }
}

#pragma clang section text = ""
