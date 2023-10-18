/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/pte.h"
#include "vm/file.h"
#include "userprog/process.h"
#include <stdio.h>

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);
static uint64_t page_hash(const struct hash_elem *p_, void *aux UNUSED);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
// lazy load 상태를 만들기 위해 사용.
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
                                    bool writable, vm_initializer *init,
                                    void *aux) {
  struct supplemental_page_table *spt = &thread_current()->spt;
  struct page *page = NULL;
  void *upage_entry = pg_round_down(upage);
  void *initializer = NULL;

  ASSERT (VM_TYPE(type) != VM_UNINIT)
  ASSERT (is_user_vaddr (upage));

  /* Check wheter the upage is already occupied or not. */
  if ((page = spt_find_page(spt, upage_entry)) == NULL) {
    /* TODO: Create the struct page, fetch the initialier according to the VM
     * type,
     * TODO: and then create "uninit" page struct by calling uninit_new. You
     * TODO: should modify the field after calling the uninit_new. */
    page = (struct page *)calloc(1, sizeof(struct page));
    if (page == NULL) {
      return false;
    }

    page->writable = writable;

    switch (type) {
    case VM_ANON:
      initializer = anon_initializer;
      break;
    case VM_FILE:
      initializer = file_backed_initializer;
      break;
    default:
      NOT_REACHED();
    }

    ASSERT (initializer != NULL);
    uninit_new(page, upage_entry, init, type, aux, initializer);

    /* Insert the page into the spt. */
    spt_insert_page(spt, page);
  }

  // spt에 page가 존재하면 true를 반환한다.
  return true;
}

/** 
 * @brief Find VA from spt and return page. On error, return NULL. 
*/
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
  ASSERT (pg_ofs(va) == 0);
  
	struct page *page = page_lookup(spt, va);
	return page;
}

/** 
 * @brief Insert PAGE into spt with validation. 
 */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;

	if (page) { // TODO - page validation
		succ = true;
		hash_insert(&spt->page_map, &page->hash_elem);
	}

	return succ;
}

/**
 * @brief spt로부터 page를 해제한다.
 */
void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	ASSERT(hash_delete(&spt->page_map, &page->hash_elem));
	vm_dealloc_page (page);
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

  ASSERT(victim != NULL);
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
  // 반환된 주소가 0으로 초기화 되어있다는 보장은 없다.
	void *kva = palloc_get_page(PAL_USER); // kva - kernel virtual address
	if (kva == NULL) {
		// 빈 페이지가 없으면 evict 수행
		return vm_evict_frame();
	}
  
  struct frame *frame = malloc(sizeof(struct frame));
  frame->kva = kva;
  frame->page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	// TODO - stack growth
  if (!vm_alloc_page_with_initializer(VM_ANON, pg_round_down(addr), true, pml4_setter, NULL)) {
    PANIC ("VM: fail to allocate an struct page in stack growth.\n");
  }

  vm_claim_page(addr);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
                         bool user UNUSED, bool write UNUSED,
                         bool not_present UNUSED) {
  struct supplemental_page_table *spt = &thread_current()->spt;
  struct page *page = NULL;
	void *upage_entry = pg_round_down(addr);

  /* Validate the fault */
  ASSERT (is_user_vaddr(addr)); // if page's type is uninit, BOOM
  // printf("[*] 💥 fault_address: %p\n", addr);

  if ((page = spt_find_page(spt, upage_entry)) != NULL) {
    // case 1. file-backed, case 2. swap-out, case 3. first stack
    if (vm_do_claim_page(page)) {
      return true;
    }
  } else {
  	/* 여기서부터는 page가 존재하지 않는 요청에 대해 처리 수행 - 명시적인 할당 요청이 없었음 */
    if ((uint64_t)f->rsp <= (uint64_t)addr && (uint64_t)addr < USER_STACK) {
      // stack growth with legitimate stack pointer
      // `CALL` 명령과 함께 rsp가 증가한 상태로 page fault가 발생해야만 OK
      vm_stack_growth(upage_entry);
      return true;
    }
  }

  return false;
  // return vm_do_claim_page (page);
}

void vm_dealloc_page_each(struct hash_elem *elem, void *aux UNUSED) {
  struct page *page = hash_entry(elem, struct page, hash_elem);
  vm_dealloc_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
// 페이지만 추가로 생성하고, frame은 생성하지 않는다.
// 페이지가 존재하지 않지만 줘야하는 경우 사용 ex) stack growth
// claim을 건다. 내꺼야! 이 주소 내꺼야 줘! spt에 내 주소(페이지)를 추가해줘!
bool
vm_claim_page (void *va UNUSED) {
	ASSERT (va != NULL);
  ASSERT (pg_ofs(va) == 0);

  if (vm_alloc_page_with_initializer(VM_ANON, va, true, pml4_setter, NULL)) {
    struct page *page = page_lookup(&thread_current()->spt, va);
	  return vm_do_claim_page (page);
  }
  
  return false;
}

/** 
 * Claim the PAGE and set up the mmu. 
 * page를 전달받아 frame을 생성하고 매핑한다.
 * 페이지가 존재하면 frame을 할당해줄 목적으로 사용, claim을 처리해준다.
 * 아이구 고객님 고생이 많으셨겠어요 ^^ 처리해 드리겠습니다.
 * pml4 - kva 연결 작업은 operation 에서 한다.
 */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
  ASSERT (frame != NULL);

	/* Set links */
	frame->page = page;
	page->frame = frame;

  // anonymous 는 0으로 채워줘야 한다.
  if (page_get_type(page) == VM_ANON) {
    memset(frame->kva, 0, PGSIZE);
  }

	return swap_in (page, frame->kva);
}

static bool page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
	struct page *page_a = hash_entry(a, struct page, hash_elem);
	struct page *page_b = hash_entry(b, struct page, hash_elem);

	return page_a->va < page_b->va;
}

static uint64_t page_hash(const struct hash_elem *p_, void *aux UNUSED) {
	const struct page *p = hash_entry(p_, struct page, hash_elem);
	return hash_bytes(&p->va, sizeof p->va);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	// hash init
	hash_init(&spt->page_map, page_hash, page_less, NULL);

	// TODO 추가적인 작업 필요
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED) {
  struct hash_iterator i;
  struct page *p, *dup_p;

  hash_first(&i, &src->page_map);
  while (hash_next(&i)) {
    p = hash_entry(hash_cur(&i), struct page, hash_elem);
    dup_p = (struct page *)calloc(1, sizeof(struct page));
    memcpy(dup_p, p, sizeof(struct page));

    // 부모 페이지에 frame이 이미 할당되어 있으면 (fault 가 이미 발생했으면) frame 내용을 복사
    if (p->frame != NULL) {
      vm_do_claim_page(dup_p);
      memcpy(dup_p->frame->kva, p->frame->kva, PGSIZE);
    }

    hash_insert(&dst->page_map, &dup_p->hash_elem);
  }

  ASSERT(hash_size(&dst->page_map) == hash_size(&src->page_map));
  return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
  // hash_apply(&spt->page_map, vm_dealloc_page_each);
}

/** 
 * @brief Returns the page containing the given virtual address, or a null pointer if no such page exists. 
 */
struct page *
page_lookup (struct supplemental_page_table *spt, const void *address) {
  struct page p;
  struct hash_elem *e;

	p.va = (void *)address;
  e = hash_find(&spt->page_map, &p.hash_elem);
  return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
}
