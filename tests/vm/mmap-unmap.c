/* Maps and unmaps a file and verifies that the mapped region is
   inaccessible afterward. */

#include <syscall.h>
#include "tests/vm/sample.inc"
#include "tests/lib.h"
#include "tests/main.h"

#define ACTUAL ((void *) 0x10000000)


void
test_main (void)
{
  int handle;
  void *map;

  CHECK ((handle = open ("sample.txt")) > 1, "open \"sample.txt\"");
  CHECK ((map = mmap (ACTUAL, 0x2000, 0, handle, 0)) != MAP_FAILED, "mmap \"sample.txt\"");
  msg ("memory is readable %d", *(int *) ACTUAL);
  msg ("memory is readable %d", *(int *) ACTUAL + 0x1000);

  munmap (map); // unmap the region

  // NOTE should not be readable, fail 메시지를 출력하지 않고 곧바로 page fault가 발생해서 exit(-1)을 하게 만들어야 함.
  fail ("unmapped memory is readable (%d)", *(int *) (ACTUAL + 0x1000)); 
  fail ("unmapped memory is readable (%d)", *(int *) (ACTUAL));
}
