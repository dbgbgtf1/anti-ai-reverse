#include "../include/runner.h"
#include "../include/generate.h"
#include "../include/puzzle_text.h"
#include <excpt.h>
#include <memoryapi.h>
#include <processenv.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winnt.h>
#include <winternl.h>
#include <winuser.h>

void
rolling_xor (uint8_t *output, uint8_t *input, uint64_t size, uint64_t *seed)
{
  for (uint64_t i = 0; i < (size + 1) / sizeof (uint64_t); i++)
    {
      ((uint64_t *)output)[i] = ((uint64_t *)input)[i] ^ *seed;
      *seed = (*seed + ((uint64_t *)input)[i]);
    }
}

#define INIT_SEED 0xdead1337beef1337ULL

int
main (int argc, char *argv[])
{
  puts ("Hello, welcome to Defcon 2027 misc01: crack_me");
  puts ("Well, set SEED envariable to decrypt me!");

  uint64_t seed = INIT_SEED;
  char seed_s[0x20];
  if (GetEnvironmentVariableA ("SEED", seed_s, 0x20))
    seed = strtoull (seed_s, NULL, 0);
  printf ("%p\n", (void *)seed);

  __try
    {
      uint8_t *text
          = VirtualAlloc (NULL, sizeof (puzzle_text) + 1,
                          MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      rolling_xor (text, puzzle_text, sizeof (puzzle_text), &seed);
      int (*func) () = (int (*) ())text;
      int ret = func ();
      uint64_t stack = ((uint64_t)&ret) & ~0xFFFFFFFFULL;
      char *flag = (char *)(stack | (uint64_t)ret);
      memcpy (text, flag, 0x40);
      printf ("Huh! you got the flag! %s\n", (char *)text);
      return 0;
    }
  __except (seed == INIT_SEED ? EXCEPTION_CONTINUE_EXECUTION
                              : EXCEPTION_EXECUTE_HANDLER)
    {
      generate ();
      return 2;
    }
}
