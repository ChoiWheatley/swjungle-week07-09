#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

/**
 * @brief union of struct page, used for VM_FILE
 * lazy file load를 위한 인자전달 구조체
 * @implements get_size_of_aux
 */
struct file_page {
	uint64_t aux_size;
	struct file *file;
	off_t ofs;
	uint8_t *upage;
	uint32_t read_bytes;
	uint32_t zero_bytes;
	bool writable;
	size_t connected_page_cnt;
	size_t connected_page_idx;
};

void vm_file_init (void);
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset);
void do_munmap (void *va);
#endif
