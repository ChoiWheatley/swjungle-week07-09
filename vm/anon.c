/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "threads/mmu.h"
#include <stdio.h>

#include "kernel/bitmap.h"
#include <round.h>

// Swap Table Info
struct bitmap *swap_bitmap;

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	uint64_t pg_cnt;

	filesys_lock_acquire();
	swap_disk = disk_get(1, 1);
	pg_cnt = disk_size(swap_disk) / 8;
	swap_bitmap = bitmap_create(pg_cnt);
	filesys_lock_release();
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva) {
  if (type != VM_ANON || page->frame->kva != kva) {
    return false;
  }

  /* Set up the handler */
  struct anon_page *anon_page = &page->anon; 
	page->operations = &anon_ops;

	// TODO - do something with kva
  anon_page->area = -1;
	page->anon = *anon_page; // FIXME 위의 FIXME에서 이어짐.

	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	if (anon_page->area == -1 || page->frame == NULL) {
    // printf("[*] swap_in failed!: %p\n", page->va);
		return false;
	}

  filesys_lock_acquire();
  disk_sector_t start_sector = anon_page->area * 8;
  for (disk_sector_t i = 0; i < 8; i++) {
    disk_read(swap_disk, start_sector + i,
              (char *)kva + i * DISK_SECTOR_SIZE);
  }
  bitmap_flip(swap_bitmap, anon_page->area);
  anon_page->area = -1;
	filesys_lock_release();

  return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
  if (anon_page->area != -1 || page->frame == NULL) {
    return false;
  }

	filesys_lock_acquire();
  anon_page->area = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
  if (anon_page->area == BITMAP_ERROR) {
    PANIC("Swap Disk is Full!");
  }

  disk_sector_t start_sector = anon_page->area * 8;
  for (disk_sector_t i = 0; i < 8; i++) {
    disk_write(swap_disk, start_sector + i,
               (char *)page->frame->kva + i * DISK_SECTOR_SIZE);
  }
	filesys_lock_release();

  return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
  if (page->frame == NULL) {
    return;
  }

	filesys_lock_acquire();
	struct anon_page *anon_page = &page->anon;
  // frame을 삭제하지 않고 frame table에 놔둬서 다른 page가 사용할 수 있도록 한다.
	filesys_lock_release();

  // unlink frame을 직접 해주어야 한다.
  pml4_clear_page(thread_current()->pml4, page->va);
  page->frame->ref_cnt -= 1;
  list_remove(&page->frame_elem);
  page->frame = NULL;
}
