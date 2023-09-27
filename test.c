#include <stdio.h>
#include <stddef.h>

struct thread {
  char stub1;
  char stub2;
  char stub3;
  char stub4;
  char elem; // 4
  char d_elem; // 5
};

int main(int argc, char const *argv[]) {
  printf("offsetof(thread::elem): %ld\n", offsetof(struct thread, elem));
  printf("offsetof(thread::d_elem): %ld\n", offsetof(struct thread, d_elem));

  return 0;
}
