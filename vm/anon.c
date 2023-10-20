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
	pg_cnt = disk_size(swap_disk) / (8 * DISK_SECTOR_SIZE);
	swap_bitmap = bitmap_create(pg_cnt);
	filesys_lock_release();
}

/* Initialize the file mapping */
bool anon_initializer(struct page *page, enum vm_type type, void *kva) {
  /* Set up the handler */
	bool success = false;
  // FIXME 현재 page는 uninit_page로 초기화된 상태. 이걸 anon_page로 캐스팅 해도
  // 되나?
  struct anon_page *anon_page = &page->anon; 

	ASSERT (type == VM_ANON);

	// TODO - do something with kva

	page->operations = &anon_ops;
	// page->frame->kva = kva;
	page->anon = *anon_page; // FIXME 위의 FIXME에서 이어짐.
	
	ASSERT (page == page->frame->page);
	success = true;
	
	return success;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	if (anon_page->area != -1 || page->frame == NULL) {
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

  // thread_current의 pml4에 할당	
	pml4_set_page(thread_current()->pml4, page->va, kva, true);
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

  pml4_clear_page(thread_current()->pml4, page->va);
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	filesys_lock_acquire();
	struct anon_page *anon_page = &page->anon;
	if (page->frame != NULL) {
		free(page->frame);
	}
	filesys_lock_release();
}
