#include "userprog/process.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "include/lib/stdio.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/exception.h"
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef VM
#include "vm/vm.h"
#endif

static struct hand_in {
  struct file *file;
  off_t ofs;
  uint8_t *upage;
  uint32_t read_bytes;
  uint32_t zero_bytes;
  bool writable;
};

static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);

struct child_info *tid_to_child_info(tid_t);

/* General process initializer for initd and other process. */
static void process_init(void) { struct thread *current = thread_current(); }

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t process_create_initd(const char *file_name) {
  char *fn_copy;
  tid_t tid;
  char filename_cp[15];

  /* Make a copy of FILE_NAME.
   * Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(filename_cp, file_name, strcspn(file_name, " ") + 1);
  memcpy(fn_copy, (void *)file_name, strlen(file_name) + 1);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(filename_cp, PRI_DEFAULT, initd, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page(fn_copy);
  return tid;
}

/* A thread function that launches first user process. */
static void initd(void *f_name) {
  printf("[*] 왔니? %p\n", f_name);
#ifdef VM
  supplemental_page_table_init(&thread_current()->spt);
#endif

  process_init();

  if (process_exec(f_name) < 0) {
    PANIC("Fail to launch initd\n");
  }
  NOT_REACHED();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t process_fork(const char *name, struct intr_frame *if_ UNUSED) {
  // TODO - do wait until child process done fork
  struct thread *cur = thread_current();
  struct list_elem *e;
  struct list *c_list = &cur->child_list;  // 자식의 유서 장부
  struct thread *child_th;
  struct child_info *ch_info;

  /* Clone current thread to new thread.*/
  tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, thread_current());
  if (tid == TID_ERROR) {  // 자식이 create가 되지 않은 경우
    return TID_ERROR;
  }
  // cur(부모)의 child_list에 위에서 create한 자식의 child_info의 c_elem이 들어가있다.
  // 방금 추가된 child_info를 tid로 찾는다.
  // 찾은 tid로 방금 생성된 thread를 찾는다.
  // 방금 생성된 thread의 fork_sema를 sema_down한다.
  // for (e = list_begin(c_list); e != list_end(c_list); e = list_next(e)) {
  //   ch_info = list_entry(e, struct child_info, c_elem);  // 자식의 유서
  //   if (tid == ch_info->pid) {  // 기다리려는 자식이 맞다면
  //     child_th = ch_info->th;  // 자식의 thread// 내 자식이 맞다!
  //     sema_down(&child_th->fork_sema);
  //     break;
  //   }
  // }
  ch_info = tid_to_child_info(tid);
  child_th = ch_info->th;
  sema_down(&child_th->fork_sema);

  if (child_th->exit_status == -1) {  // 자식이 fork가 제대로 되지 않고 종료된 경우
    return TID_ERROR;
  }
  return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool duplicate_pte(uint64_t *pte, void *va, void *aux) {
  struct thread *current = thread_current();
  struct thread *parent = (struct thread *)aux;
  void *parent_page;
  void *newpage;
  bool writable;

  /* 1. TODO: If the parent_page is kernel page, then return immediately. */
  if (is_kernel_vaddr(va)) {
    return true;
  }

  /* 2. Resolve VA from the parent's page map level 4. */
  parent_page = pml4_get_page(parent->pml4, va);
  if (parent_page == NULL) {
    return false;
  }

  /* 3. TODO: Allocate new PAL_USER page for the child and set result to
   *    TODO: NEWPAGE.
   * 유저 페이지 할당
   */
  newpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (newpage == NULL) {
    return false;
  }

  /* 4. TODO: Duplicate parent's page to the new page and
   *    TODO: check whether parent's page is writable or not (set WRITABLE
   *    TODO: according to the result).
   * 기존 페이지를 새 페이지에 복제한다.
   * */
  memcpy(newpage, parent_page, PGSIZE);
  writable = is_writable(pte);
  /* 5. Add new page to child's page table at address VA with WRITABLE
   *    permission.
   * 페이지에 권한부여
   */
  if (!pml4_set_page(current->pml4, va, newpage, writable)) {
    /* 6. TODO: if fail to insert page, do error handling.
     * 에러 핸들링
     */
    return false;
  }
  return true;
}
#endif

/**
 * @brief A thread function that copies parent's execution context.
 * @note - parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function.
 * @note - process_exec과의 유일한 차이점은 parent의 컨텍스트와 file, lock,
 * page를 몽땅 복사한다는 점이다. Project 3 Virtual Memory에서 Copy On Write를
 * 하기 전까지는 모든 내용을 복제하는 것으로 보인다.
 */
static void __do_fork(void *aux) {
  struct intr_frame if_;
  struct thread *parent = (struct thread *)aux; // `thread_current()` of parent
  struct thread *current = thread_current();
  struct intr_frame *parent_if = &parent->bf;
  bool succ = true;

  /* 1. Read the cpu context to local stack. */
  memcpy((void *)&if_, parent_if, sizeof(struct intr_frame));

  /* 2. Duplicate PT */
  current->pml4 = pml4_create();
  if (current->pml4 == NULL)
    goto error;

  process_activate(current);
#ifdef VM
  supplemental_page_table_init(&current->spt);
  if (!supplemental_page_table_copy(&current->spt, &parent->spt))
    goto error;
#else
  // TODO - 페이지 테이블 복제
  if (!pml4_for_each(parent->pml4, duplicate_pte, parent))
    goto error;
#endif

  /* TODO: File Descriptor Table 복제
   * Hint) To duplicate the file object, use `file_duplicate`
   *       in include/filesys/file.h. Note that parent should not return
   *       from the fork() until this function successfully duplicates
   *       the resources of parent.
   */
  // 파일을 읽지 못한다는 이유로 처형하는 코드 삭제
  // if (parent->fd_idx == FDCOUNT_LIMIT)
  //   goto error;

  for (int i = 2; i < FDCOUNT_LIMIT; i++) {
    if (parent->fd_table[i] != NULL) {
      current->fd_table[i] = file_duplicate(parent->fd_table[i]);
    } else {
      current->fd_table[i] = NULL;
    }
  }
  current->fd_idx = parent->fd_idx;
  if_.R.rax = 0;
  process_init();

  /* Finally, switch to the newly created process. */
  sema_up(&current->fork_sema);
  if (succ)
    do_iret(&if_);

error:  // fork가 제대로 되지 않은 경우
  current->exit_status = -1;
  sema_up(&current->fork_sema);
  exit(-1);
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int process_exec(void *f_name) {
  char *file_name = f_name;
  bool success;
  int i;
  char *argv[128] = {
      0,
  };
  char *token, *save_ptr; // token화 하기 위한 변수
  int argc = 0;  // argument 개수

  for (token = strtok_r(file_name, " ", &save_ptr); token != NULL;
       token = strtok_r(NULL, " ", &save_ptr)) {
    /* 인자 파싱 */
    argv[argc] = token;
    argc++;
  }

  /* Intr_frame 초기화 */
  struct intr_frame _if;
  _if.ds = _if.es = _if.ss = SEL_UDSEG;
  _if.cs = SEL_UCSEG;
  _if.eflags = FLAG_IF | FLAG_MBS;

  /* 현재 실행 중인 스레드의 컨텍스트 종료 */
  process_cleanup();

  /* 이후에 바이너리 파일 로드 */
  success = load(argv[0], &_if);
  if (!success) {
    palloc_free_page(file_name);
    return -1;
  }

  /* 유저스택에 인자 추가 */
  argument_stack(argc, argv, &_if);
  palloc_free_page(file_name);
  
  /* 프로세스 전환하여 실행 */
  do_iret(&_if);
  NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int process_wait(tid_t child_tid UNUSED) {
  // struct thread *curr = thread_current();
  // struct thread *child_th;
  // struct list *c_list = &curr->child_list;  // 호적
  // struct list_elem *e;
  struct child_info *ch_info;
  // bool is_child = false;  // 받은 주민번호가 내 자식의 것이 맞는가

  /* 호적을 순회하며 내 자식의 주민번호인지 확인 */
  // if (!list_empty(c_list)) {  // 자식이 존재한다면
  //   for (e = list_begin(c_list); e != list_end(c_list); e = list_next(e)) {
  //     ch_info = list_entry(e, struct child_info, c_elem);  // 자식의 유서
  //     if (child_tid == ch_info->pid) {  // 기다리려는 자식이 맞다면
  //       child_th = ch_info->th;  // 자식의 thread
  //       is_child = true;  // 내 자식이 맞다!
  //       break;
  //     }
  //   }
  // }
  // if (is_child) {  // 기다리려는 자식이 내 자식이 맞는 경우
  //   bool exited = ch_info->exited;
  //   if (exited == 0) {  // 자식이 아직 살아있다면
  //     sema_down(&child_th->wait_sema);  // 자식이 죽을 때까지 기다림
  //   }

  //   int child_status = ch_info->exit_status;  // 자식의 사망 원인 조사
  //   list_remove(e);  // 호적에서 제거
  //   free(ch_info);  // 주민등록 말소 (사망신고 처리)
  //   return child_status;
  // } else {  // 기다리려는 자식이 내 자식이 아닌 경우
  //   return -1;
  // }
  
  if ((ch_info = tid_to_child_info(child_tid)) != NULL) {
    bool exited = ch_info->exited;
    if (exited == 0) {
      sema_down(&ch_info->th->wait_sema);
    }
    int child_status = ch_info->exit_status;  // 자식의 사망 원인 조사
    list_remove(&ch_info->c_elem);  // 호적에서 제거
    free(ch_info);  // 주민등록 말소 (사망신고 처리)
    return child_status;
  } else {  // 기다리려는 자식이 내 자식이 아닌 경우
    return -1;
  }
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void) {
  struct thread *t = thread_current();
  /* TODO: Your code goes here.
   * TODO: Implement process termination message (see
   * TODO: project2/process_termination.html).
   * TODO: We recommend you to implement process resource cleanup here.
   */
  /* file 해제 */
  for (int i = 2; i < t->fd_idx; i++) {
    if (t->fd_table[i] != NULL) {
      close(i);
    }
  }
  palloc_free_multiple(t->fd_table, FDT_PAGES);
  file_close(t->running); // 실행중인 파일 닫기

  /* 부모가 가진 내 유서를 수정. { exit_status(사망 원인), exited(사망 여부) } */
  if (t->parent != NULL) {
    struct list *c_list = &t->parent->child_list;
    for (struct list_elem *e = list_begin(c_list); e != list_end(c_list); e = list_next(e)) {
      struct child_info *my_info = list_entry(e, struct child_info, c_elem);
      if (t->tid == my_info->pid) {
        my_info->exit_status = t->exit_status;
        my_info->exited = 1;
        break;
      }
    }
  }

  /* 내가 가진 자식들의 유서 전부 폐기 */
  while (!list_empty(&t->child_list)) {
    struct child_info *ch_info = list_entry(list_pop_front(&t->child_list), struct child_info, c_elem);
    ch_info->th->parent = NULL;
    free(ch_info);
  }

  /* 나의 죽음을 기다리던 부모가 있다면 깨우기 */
  sema_up(&t->wait_sema);

  process_cleanup();
}

/* Free the current process's resources. */
static void process_cleanup(void) {
  struct thread *curr = thread_current();

#ifdef VM
  supplemental_page_table_kill(&curr->spt);
#endif

  uint64_t *pml4;
  /* Destroy the current process's page directory and switch back
   * to the kernel-only page directory. */
  pml4 = curr->pml4;
  if (pml4 != NULL) {
    /* Correct ordering here is crucial.  We must set
     * cur->pagedir to NULL before switching page directories,
     * so that a timer interrupt can't switch back to the
     * process page directory.  We must activate the base page
     * directory before destroying the process's page
     * directory, or our active page directory will be one
     * that's been freed (and cleared). */
    curr->pml4 = NULL;
    pml4_activate(NULL);
    pml4_destroy(pml4);
  }
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void process_activate(struct thread *next) {
  /* Activate thread's page tables. */
  pml4_activate(next->pml4);

  /* Set thread's kernel stack for use in processing interrupts. */
  tss_update(next);
}

/**
 * @brief 초기화된 유저 스택공간에 직접 인자를 추가한다.
 */
void argument_stack(int argc, char **argv, struct intr_frame *if_) {
  char *argv_addr[128];

  for (int i = argc - 1; i >= 0; i--) {
    int argv_len = strlen(argv[i]);
    if_->rsp = if_->rsp - (argv_len + 1);
    memcpy((void *)if_->rsp, argv[i], argv_len + 1);
    argv_addr[i] = (char *)if_->rsp;
  }

  while (if_->rsp % 8 != 0) {
    if_->rsp--;
    *(uint8_t *)if_->rsp = 0;
  }

  for (int i = argc; i >= 0; i--) {
    if_->rsp = if_->rsp - 8;
    if (i == argc) {
      memset((void *)if_->rsp, 0, sizeof(char **));
    } else {
      memcpy((void *)if_->rsp, &argv_addr[i], sizeof(char **));
    }
  }

  if_->R.rdi = argc;
  if_->R.rsi = if_->rsp;

  if_->rsp = if_->rsp - 8;
  memset((void *)if_->rsp, 0, sizeof(void *));
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
  unsigned char e_ident[EI_NIDENT];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};

struct ELF64_PHDR {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool load(const char *file_name, struct intr_frame *if_) {
  struct thread *t = thread_current();
  struct ELF ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pml4 = pml4_create();
  if (t->pml4 == NULL)
    goto done;
  process_activate(thread_current());

  if (t->running != NULL) {
    file_close(t->running);
    t->running = NULL;
  }

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL) {
    file_close(file);
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  t->running = file;
  file_deny_write(file); // 실행 중인 파일은 수정할 수 없다.

  /* Read and verify executable header. */
  lock_acquire(inode_get_lock(file_get_inode(file)));
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 ||
      ehdr.e_machine != 0x3E // amd64
      || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) ||
      ehdr.e_phnum > 1024) {
    lock_release(inode_get_lock(file_get_inode(file)));
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }
  lock_release(inode_get_lock(file_get_inode(file)));

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    lock_acquire(inode_get_lock(file_get_inode(file)));
    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr) {
      lock_release(inode_get_lock(file_get_inode(file)));
      goto done;
    }
    lock_release(inode_get_lock(file_get_inode(file)));
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
    case PT_NULL:
    case PT_NOTE:
    case PT_PHDR:
    case PT_STACK:
    default:
      /* Ignore this segment. */
      break;
    case PT_DYNAMIC:
    case PT_INTERP:
    case PT_SHLIB:
      goto done;
    case PT_LOAD:
      if (validate_segment(&phdr, file)) {
        bool writable = (phdr.p_flags & PF_W) != 0;
        uint64_t file_page = phdr.p_offset & ~PGMASK;
        uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
        uint64_t page_offset = phdr.p_vaddr & PGMASK;
        uint32_t read_bytes, zero_bytes;
        if (phdr.p_filesz > 0) {
          /* Normal segment.
           * Read initial part from disk and zero the rest. */
          read_bytes = page_offset + phdr.p_filesz;
          zero_bytes =
              (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
        } else {
          /* Entirely zero.
           * Don't read anything from disk. */
          read_bytes = 0;
          zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
        }
        if (!load_segment(file, file_page, (void *)mem_page, read_bytes,
                          zero_bytes, writable))
          goto done;
      } else
        goto done;
      break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(if_))
    goto done;

  /* Start address. */
  if_->rip = ehdr.e_entry;

  /* TODO: Your code goes here.
   * TODO: Implement argument passing (see project2/argument_passing.html). */

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  // file_close(file); load에서 file을 닫으면 lock이 풀린다.
  return success;
}

struct child_info *tid_to_child_info(tid_t child_tid) {
  struct thread *t = thread_current();
  struct list *c_list = &t->child_list;
  struct list_elem *e;
  struct child_info *ch_info;
  for (e = list_begin(c_list); e != list_end(c_list); e = list_next(e)) {
    ch_info = list_entry(e, struct child_info, c_elem);  // 자식의 유서
    if (ch_info->pid == child_tid) {  // 기다리려는 자식이 맞다면 자식의 thread// 내 자식이 맞다!
      return ch_info;
    }
  }
  return NULL;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Phdr *phdr, struct file *file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (uint64_t)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void *)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page(void *upage, void *kpage, bool writable);

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool install_page(void *upage, void *kpage, bool writable) {
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
   * address, then map our page there. */
  return (pml4_get_page(t->pml4, upage) == NULL &&
          pml4_set_page(t->pml4, upage, kpage, writable));
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Do calculate how to fill this page.
     * We will read PAGE_READ_BYTES bytes from FILE
     * and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t *kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      printf("fail\n");
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool setup_stack(struct intr_frame *if_) {
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
    if (success)
      if_->rsp = USER_STACK;
    else
      palloc_free_page(kpage);
  }
  return success;
}


#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

/**
 * @brief Load the segment from the file
 * This called when the first page fault occurs on address VA.
 * VA is available when calling this function.
 *
 * @param page pointer to the page
 * @param aux file pointer that contains loadable object
 */
static bool lazy_load_segment(struct page *page, void *aux) {
  // cast to file from aux
  struct thread *t = thread_current();
  struct hand_in *hand_in = aux;

  // unpack hand_in struct pointer
  struct file *file = hand_in->file;
  off_t ofs = hand_in->ofs;
  uint8_t *upage = hand_in->upage;
  uint32_t read_bytes = hand_in->read_bytes;
  uint32_t zero_bytes = hand_in->zero_bytes;
  bool writable = hand_in->writable;

  /* copy of load_segment when USERPROG */
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  /* Do calculate how to fill this page.
    * We will read PAGE_READ_BYTES bytes from FILE
    * and zero the final PAGE_ZERO_BYTES bytes. */

  /* Get a page of memory. */
  uint8_t *kpage = page->frame->kva;
  if (kpage == NULL)
    return false;

  /* Load this page. */
  if (file_read(file, kpage, read_bytes) != (int)read_bytes) {
    return false;
  }
  memset(kpage + read_bytes, 0, zero_bytes);

  // NOTE - USERPROG 시절 load_segment를 복사함. 문제생기면 여기임.
  ASSERT (page->va == upage);

  // pml4_set_page(t->pml4, page->va, page->frame->kva, writable);
  free(aux);

  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  struct hand_in *hand_in;

  while (read_bytes > 0 || zero_bytes > 0) {
    /* Do calculate how to fill this page.
     * We will read PAGE_READ_BYTES bytes from FILE
     * and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    hand_in = (struct hand_in *) malloc(sizeof(struct hand_in));
    *hand_in = (struct hand_in) {
      .file = file,
      .ofs = ofs,
      .upage = upage,
      .read_bytes = page_read_bytes,
      .zero_bytes = page_zero_bytes,
      .writable = writable
    };

    /** 
     * Set up aux to pass information to the lazy_load_segment. 
     * NOTE - possibility of memory leak (file)
     */
    if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable,
                                        lazy_load_segment, hand_in))
      return false;

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool setup_stack(struct intr_frame *if_) {
  bool success = false;
  void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

  if (vm_alloc_page_with_initializer(VM_ANON, stack_bottom, true, NULL, NULL)) {
    /* Map the stack on stack_bottom and claim the page immediately.
    * If success, set the rsp accordingly.
    * You should mark the page is stack. */
    if_->rsp = USER_STACK;
    /* TODO: You should mark the page is stack. */
    success = true;
  }

  return success;
}
#endif /* VM */
