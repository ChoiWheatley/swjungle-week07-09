/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/mmu.h"
#include "threads/malloc.h" // free

#include <string.h> // memcpy

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	// uninit_page로 초기화된 union을 file_page로 덮어씌운다. (using aux given by mmap)
	void *aux = page->uninit.aux;
	struct file_page *file_page = (struct file_page *) aux;
	memcpy(&page->file, file_page, sizeof(struct file_page));
	
	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	struct thread *cur = thread_current();
	// dirty bit를 확인해서, 변경된 기록이 있으면 파일에 내용을 쓰고 destory 수행
	if (pml4_is_dirty(cur->pml4, page->va)) {
		file_seek(page->file.file, page->file.ofs);
		file_write(page->file.file, page->va, page->file.read_bytes);
	}
	file_close(page->file.file);
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
}

/* Do the munmap */
void do_munmap(void *addr) {}
