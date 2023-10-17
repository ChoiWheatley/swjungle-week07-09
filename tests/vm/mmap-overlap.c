/* Verifies that overlapping memory mappings are disallowed. */

#include <syscall.h>
#include "tests/vm/sample.inc"
#include "tests/lib.h"
#include "tests/main.h"

void
test_main (void)
{
  char *start = (char *) 0x10000000;
  int fd[2];

  CHECK ((fd[0] = open ("zeros")) > 1, "open \"zeros\" once");
  CHECK (mmap (start, 4096, 0, fd[0], 0) != MAP_FAILED, "mmap \"zeros\"");

  // TODO - 반복문 안에서 필요로 하는 페이지 개수만큼 순회하다가 모든 페이지가
  // 연속적으로 채워질 수 있으면 그때서야 비로소 vm_alloc을 호출할 수 있다.
  // 그 외에는 MAP_FAILED을 반환해야 한다.

  CHECK ((fd[1] = open ("zeros")) > 1 && fd[0] != fd[1],
         "open \"zeros\" again");
  CHECK (mmap (start, 4096, 0, fd[1], 0) == MAP_FAILED,
         "try to mmap \"zeros\" again");
}
