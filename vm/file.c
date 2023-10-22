/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/mmu.h"
#include "threads/malloc.h" // free

#include <string.h> // memcpy
#include "filesys/inode.h"

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
	bool success = false;
	struct file_page *file_page UNUSED = &page->file;

	ASSERT (file_page->file != NULL);
	ASSERT (page->frame != NULL);
	ASSERT (page->frame->kva == kva);

	// kva에 file의 내용을 읽어온다
	filesys_lock_acquire();
	lock_acquire(inode_get_lock(file_get_inode(file_page->file)));
	file_seek(file_page->file, file_page->ofs);
	if (file_read(file_page->file, kva, file_page->read_bytes) !=
			file_page->read_bytes) {
		goto done;
	}
	memset((char *)kva + file_page->read_bytes, 0, file_page->zero_bytes);

	success = true;

	done:
		lock_release(inode_get_lock(file_get_inode(file_page->file)));
		filesys_lock_release();
		return success;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	if (pml4_is_dirty(thread_current()->pml4, page->va) == false) {
		pml4_clear_page(thread_current()->pml4, page->va);
		return true;
	}

	ASSERT (file_page->file != NULL);
	ASSERT (page->frame != NULL);

	// kva에 file의 내용을 쓴다
	filesys_lock_acquire();
	lock_acquire(inode_get_lock(file_get_inode(file_page->file)));
	file_seek(file_page->file, file_page->ofs);
	file_write(file_page->file, page->va, file_page->read_bytes);
	lock_release(inode_get_lock(file_get_inode(file_page->file)));
	filesys_lock_release();

	return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	struct thread *cur = thread_current();
	if (page->frame == NULL) {
		// frame이 없다면 write_back 할 내용이 없다.
		return;
	}

	ASSERT (file_page->file != NULL);

	filesys_lock_acquire();
	lock_acquire(inode_get_lock(file_get_inode(file_page->file)));
	// dirty bit를 확인해서, 변경된 기록이 있으면 파일에 내용을 쓰고 destory 수행
	if (pml4_is_dirty(cur->pml4, page->va)) {
		file_seek(page->file.file, page->file.ofs);
		file_write(page->file.file, page->va, page->file.read_bytes);
	}
	lock_release(inode_get_lock(file_get_inode(file_page->file)));
	filesys_lock_release();

	// file의 첫번째 페이지일 경우 같은 file에 대한 모든 페이지를 삭제하고 file을 닫는다
	if (file_page->connected_page_idx == 0) {
		for (size_t i = 1; i < file_page->connected_page_cnt; i++) {
			struct page *p = spt_find_page(&cur->spt, page->va + i * PGSIZE);
			if (p != NULL) {
				spt_remove_page(&cur->spt, p);
			}
		}
		// TODO 안전하게 close할 방법을 찾아야 함.
		// filesys_lock_acquire();
		// file_close(file_page->file);
		// filesys_lock_release();
	}

	// unlink frame을 직접 해주어야 한다.
	pml4_clear_page(cur->pml4, page->va);
	page->frame->ref_cnt -= 1;
	page->frame->page = NULL;
	page->frame = NULL;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
}

/* Do the munmap */
void do_munmap(void *addr) {}
