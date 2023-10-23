/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/pte.h"
#include "vm/file.h"
#include "userprog/process.h"
#include <stdio.h>

#include <string.h> // memcpy
#include "threads/mmu.h" // pml4 set

// frame table: victim 선청을 위한 자료구조
struct list frame_table;

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
  list_init(&frame_table);
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

    page->writable = writable;

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

static bool frame_less (struct list_elem *a, struct list_elem *b) {
  struct frame *frame_a = list_entry(a, struct frame, elem);
  struct frame *frame_b = list_entry(b, struct frame, elem);

  return frame_a->ref_cnt < frame_b->ref_cnt;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
  struct list_elem *e = NULL;
  if (list_empty(&frame_table)) {
    return NULL; // TODO kernel panic?
  }

  // // policy: FIFO
  // e = list_pop_front(&frame_table);
  // list_push_back(&frame_table, e);

  // policy: ref_cnt가 가장 작은 frame을 victim으로 선정
  e = list_min(&frame_table, frame_less, NULL);
  list_remove(e);
  list_push_back(&frame_table, e);

  victim = list_entry(e, struct frame, elem);

  ASSERT (victim->ref_cnt <= 1);

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
  if (victim == NULL) {
    return NULL; // TODO kernel panic?
  }
  
  if (list_empty (&victim->page_list)) {
    return victim;
  }

  // page와 frame을 분리
  while (!list_empty (&victim->page_list)) {
    // swap out page element and unlink it
    struct list_elem *e = list_pop_front (&victim->page_list);
    struct page *page = list_entry(e, struct page, frame_elem);
    
    swap_out(page);
    pml4_clear_page(thread_current()->pml4, page->va);
    victim->ref_cnt -= 1;
    page->frame = NULL;
    list_remove(&page->frame_elem);
  }

  ASSERT(victim->ref_cnt == 0 && list_empty(&victim->page_list));
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
  list_init(&frame->page_list);
  frame->ref_cnt = 0;

  list_push_back(&frame_table, &frame->elem); // 생성한 frame 관리

	ASSERT (frame != NULL);
	ASSERT (list_empty(&frame->page_list));
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
  if (page->writable == false) {
    return false;
  }

  if (page->frame->ref_cnt <= 1) {
    // reference가 하나 (나 자신)이면 그대로 써도 된다.
    pml4_set_page(thread_current()->pml4, page->va, page->frame->kva, page->writable); // cow
    return true;
  }

  struct frame *dup_frame = vm_get_frame();
  memcpy(dup_frame->kva, page->frame->kva, PGSIZE);

  // unlink frame
  page->frame->ref_cnt -= 1; 
  list_remove(&page->frame_elem);

  // link page to frame
  page->frame = dup_frame;
  list_push_back(&dup_frame->page_list, &page->frame_elem); // link page to frame
  dup_frame->ref_cnt += 1;

  pml4_set_page(thread_current()->pml4, page->va, dup_frame->kva, page->writable); // cow

  return true;
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
                         bool user UNUSED, bool write UNUSED,
                         bool not_present UNUSED) {
  struct supplemental_page_table *spt = &thread_current()->spt;
  struct page *page = NULL;
	void *upage_entry = pg_round_down(addr);

  /* Validate the fault */
  if (is_user_vaddr(addr) == false) { // if page's type is uninit, BOOM
    return false;
  }
  // printf("[*] 💥 fault_address: %p\n", addr);

  if ((page = spt_find_page(spt, upage_entry)) != NULL) {
    if (page->frame == NULL) {
      return vm_do_claim_page(page);
    } else {
      ASSERT(write == true);
      return vm_handle_wp(page);
    }
  } else {
  	/* 여기서부터는 page가 존재하지 않는 요청에 대해 처리 수행 - 명시적인 할당 요청이 없었음 */
    if ((uint64_t)f->rsp <= (uint64_t)addr && (uint64_t)addr < USER_STACK) {
      // stack growth with legitimate stack pointer
      // `CALL` 명령과 함께 rsp가 증가한 상태로 page fault가 발생해야만 OK
      vm_stack_growth(upage_entry);
      struct page *_p = spt_find_page(spt, upage_entry);
      if (_p != NULL) {
        // pml4_clear_page(thread_current()->pml4, _p->va);
        pml4_set_page(thread_current()->pml4, _p->va, _p->frame->kva, false); // cow
      } else {
        return false;
      }

      return true;
    }
  }

  return false;
  // return vm_do_claim_page (page);
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
	// frame->page = page;
  list_push_back(&frame->page_list, &page->frame_elem);
	page->frame = frame;
  frame->ref_cnt += 1;

  // anonymous 는 0으로 채워줘야 한다.
  if (page_get_type(page) == VM_ANON) {
    memset(frame->kva, 0, PGSIZE);
  }

  bool success = swap_in (page, frame->kva);
  if (success) {
    pml4_set_page(thread_current()->pml4, page->va, frame->kva, false); // cow
  }

	return success;
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

/**
 * @brief Get the size of aux object
 * @note 모든 aux 인자 전달 구조체는 첫번째 필드로 size를 가지고 있다.
 * @param aux 
 * @return uint64_t 
 */
static uint64_t get_size_of_aux(void *aux) {
  return *(uint64_t *)aux;
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED) {
  struct hash_iterator i;
  struct page *p, *dup_p;

  // 현재 child thread 실행중인 상태
  hash_first(&i, &src->page_map);
  while (hash_next(&i)) {
    p = hash_entry(hash_cur(&i), struct page, hash_elem);
    dup_p = (struct page *)calloc(1, sizeof(struct page));
    memcpy(dup_p, p, sizeof(struct page));

    if (p->operations->type == VM_UNINIT) {
      // 부모 페이지에 frame이 할당되어 있지 않으면 (fault 가 발생하지 않았으면) aux를 복사
      uint64_t aux_size = get_size_of_aux(p->uninit.aux);
      dup_p->uninit.aux = calloc(1, aux_size);

      // TODO file duplicate 해서 넘겨주자
      
      memcpy(dup_p->uninit.aux, p->uninit.aux, aux_size);
    } else {
      // 부모 페이지에 frame이 이미 할당되어 있으면 (fault 가 이미 발생했으면) reference count만 증가
      dup_p->frame = p->frame;
      dup_p->frame->ref_cnt += 1;

      // 전부 read only로 설정하고, 나중에 write가 발생하면 fault가 발생하도록 한다.
      pml4_set_page(thread_current()->pml4, p->va, dup_p->frame->kva, false); // cow
    }

    hash_insert(&dst->page_map, &dup_p->hash_elem);
  }

  ASSERT(hash_size(&dst->page_map) == hash_size(&src->page_map));
  return true;
}

static void vm_dealloc_page_each(struct hash_elem *e, void *aux UNUSED) {
  struct page *p = hash_entry(e, struct page, hash_elem);
  // destory가 호출되어도 frame을 free 시키지 않으므로 모든 페이지에 대해 dealloc page 수행 가능
  vm_dealloc_page(p); 
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
  hash_clear(&spt->page_map, vm_dealloc_page_each);
  ASSERT (hash_size(&spt->page_map) == 0);
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
