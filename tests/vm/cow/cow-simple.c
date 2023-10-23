/* Checks if fork is implemented properly with copy-on-write */

#include <string.h>
#include <syscall.h>
#include <stdio.h>
#include <stdint.h>
#include "tests/lib.h"
#include "tests/main.h"
#include "tests/vm/large.inc"

#define CHUNK_SIZE (128 * 1024)

static char buffer[CHUNK_SIZE + 1];

void
test_main (void)
{
	pid_t child;
	void *pa_parent;
	void *pa_child;
	// char *buf = "Lorem ipsum";
	char buffer_local[2048];

	// CHECK (memcmp (buf, large, strlen (buf)) == 0, "check data consistency");
	// pa_parent = get_phys_addr((void*)large);

	// child = fork ("child");
	// if (child == 0) {
	// 	CHECK (memcmp (buf, large, strlen (buf)) == 0, "check data consistency");

	// 	pa_child = get_phys_addr((void*)large);
	// 	CHECK (pa_parent == pa_child, "two phys addrs should be the same.");

	// 	large[0] = '@';
	// 	CHECK (memcmp (buf, large, strlen (buf)) != 0, "check data change");

	// 	pa_child = get_phys_addr((void*)large);
	// 	CHECK (pa_parent != pa_child, "two phys addrs should not be the same.");
	// 	return;
	// }
	// wait (child);
	// CHECK (pa_parent == get_phys_addr((void*)large), "two phys addrs should be the same.");
	// CHECK (memcmp (buf, large, strlen (buf)) == 0, "check data consistency");
	
	/// Child Read
	printf("\n[*] Child Read\n\n");
	
	int handle;
	
	CHECK ((handle = open("sample.txt")) > 1, "open \"sample.txt\"");
	
	CHECK (read(handle, buffer, CHUNK_SIZE) > 1, "부모: read \"sample.txt\"");
	printf("[*] parent read data: %s\n", buffer);

	pa_parent = get_phys_addr((void *) buffer);
	
	printf("[*] 🍴 포크하기 직전!!\n");
	
	child = fork("child");
	if (child == 0) {
		// child process
		printf("[*] child process\n");
		pa_child = get_phys_addr((void *) buffer);
    CHECK(pa_parent == pa_child,
          "two phys addrs should be the same. (%p), (%p)", pa_parent, pa_child);

		seek(handle, 0);
    CHECK (read(handle, buffer, CHUNK_SIZE) > 1, "자식: read \"sample.txt\" 읽는다.");
		
		printf("read bytes: %s\n", buffer);
		
		pa_child = get_phys_addr((void *) buffer);
		CHECK (pa_parent != pa_child, "two phys addrs should not be the same. (%p), (%p)", pa_parent, pa_child);
		return;
	} else {
		// parent process
		wait (child);
		printf("[*] parent process end\n");
		CHECK (pa_parent == get_phys_addr((void *) buffer), "two phys addrs should be the same.");
	}

	return;
}

