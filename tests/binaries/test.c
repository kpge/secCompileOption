#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* checksec's trap: a symbol whose NAME contains the canary marker but has
   nothing to do with stack protection. A checker that substring-matches
   __stack_chk_fail must not report a canary. Ported from
   checksec tests/binaries/test.c. */
int false__stack_chk_fail(int a) { return a; }

int main(int argc, char **argv) {
  char buf[16];
  int (*op)(int) = false__stack_chk_fail;

  if (argc > 1)
    strcpy(buf, argv[1]);
  else
    strcpy(buf, "test");

  printf("%s,%d\n", buf, op(42));
  return 0;
}
