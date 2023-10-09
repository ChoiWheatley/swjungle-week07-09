#include "userprog/syscall.h"
#include "lib/stdio.h"
#include "lib/user/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>
#include <stdbool.h>
#include <string.h>

#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "threads/palloc.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */


void check_address(const void*);
void syscall_entry(void);
void syscall_handler(struct intr_frame *);

void halt(void);
void exit(int status);
pid_t fork(const char *thread_name);
int exec(const char *file);
int wait(pid_t pid);

bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int add_file_to_fd_table(struct file *file);
int filesize(int fd);
struct file *fd_to_file(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
void delete_file_from_fd_table(int fd);

int dup2(int oldfd, int newfd);

/**
 * @brief 사용자 주소가 유효한지 여부를 판단한다. 두 가지 검사를 수행한다.
 * 1. 주소값이 KERN_BASE보다 크다면 커널주소를 참조하려고 하기 때문에 page
 * fault를 발생시켜 프로세스를 종료시켜야 한다.
 * 2. 할당이 안된 영역을 참조하려고 한다면 segfault를 발생시켜 프로세스를
 * 종료시켜야 한다.
 *
 * @param uaddr 유저 프로그램이 syscall을 통해 요청한 주소
 * @return 주소가 유효한지 여부
 * @note 해당 함수는 유저 프로그램을 종료시켜줍니다.
 */
void check_address(const void *uaddr) {
  if (is_kernel_vaddr(uaddr) || pml4_get_page(thread_current()->pml4, uaddr) == NULL) {
		exit(-1);
  } 
}

void syscall_init(void) {
  write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG)
                                                               << 32);
  write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

  /* The interrupt service rountine should not serve any interrupts
   * until the syscall_entry swaps the userland stack to the kernel
   * mode stack. Therefore, we masked the FLAG_FL. */
  write_msr(MSR_SYSCALL_MASK,
            FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED) {
  // TODO: Your implementation goes here.
  switch (f->R.rax) {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      exit(f->R.rdi);
      break;
    case SYS_FORK:
      thread_current()->bf = *f;
      f->R.rax = fork(f->R.rdi);
      break;
    case SYS_EXEC:
      exec(f->R.rdi);
      break;
    case SYS_WAIT:
      f->R.rax = wait(f->R.rdi);
      break;
    case SYS_CREATE:
      f->R.rax = create(f->R.rdi, f->R.rsi);
      break;
    case SYS_REMOVE:
      f->R.rax = remove(f->R.rdi);
      break;
    case SYS_OPEN:
      f->R.rax = open(f->R.rdi);
      break;
    case SYS_FILESIZE:
      f->R.rax = filesize(f->R.rdi);
      break;
    case SYS_READ:
      f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
      break;
    case SYS_WRITE:
      f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
      break;
    case SYS_SEEK:
      seek(f->R.rdi, f->R.rsi);
      break;
    case SYS_TELL:
      f->R.rax = tell(f->R.rdi);
      break;
    case SYS_CLOSE:
      close(f->R.rdi);
      break;
    default:
      printf("system call!\n");
      thread_exit();
  }
}

// SECTION - Project 2 USERPROG SYSTEM CALL
// SECTION - Process based System Call
void halt(void) { 
  power_off(); 
}

void exit(int status) {
  struct thread *t = thread_current();
  t->exit_status = status;
  printf("%s: exit(%d)\n", t->name, status);
  thread_exit();
}

/**
 * @brief clone parent process's context called by syscall handler
 * 
 * @param thread_name 
 * @return pid_t negative if errr occured, else positive number
 */
pid_t fork(const char *thread_name) {
  check_address(thread_name);
  return process_fork(thread_name, NULL);
}

int exec(const char *file) {
  check_address(file);

  uint8_t *page;
  if((page = palloc_get_page(PAL_USER)) == NULL) {
    return -1;
  }
  memcpy((void *)page, file, strlen(file) + 1);

  int success = process_exec((void *)page);
  // free page if unsuccesful

  return success;
}

int wait(pid_t pid) { 
  return process_wait(pid); 
}
//! SECTION - Process based System Call
// SECTION - File based System Call
bool create(const char *file, unsigned initial_size) {
  check_address(file);
  return filesys_create(file, initial_size);
}

bool remove(const char *file) {
  check_address(file);
  return filesys_remove(file);
}

int open(const char *file) {
  check_address(file);
  struct thread *t = thread_current();
  struct file *file_obj = filesys_open(file);
  if (file_obj == NULL) {
    return -1;
  }
  // if (!strcmp(t->name, file)) {
  //   file_deny_write(file_obj);
  // }
  int fd = add_file_to_fd_table(file_obj);

  if (fd == -1) {
    file_close(file_obj);
  }
  return fd;
}

int add_file_to_fd_table(struct file *file) {
	struct thread *t = thread_current();
	struct file **fdt = t->fd_table;
	int i;
	// while (fdt[t->fd_idx] != NULL && t->fd_idx < FDCOUNT_LIMIT) {
	// 	t->fd_idx++;
	// }

	// if (t->fd_idx >= FDCOUNT_LIMIT) {
	// 	return -1;
	// }
	// fdt[t->fd_idx] = file;
	// return t->fd_idx;
  int fd = -1;
  for (i = 2; i < FDCOUNT_LIMIT; i++) {
    if (fdt[i] == NULL) {
      fdt[i] = file;
      fd = i;
      if (i > t->fd_idx)
        t->fd_idx = i;
      break;
    }
  }
  if (i == FDCOUNT_LIMIT)
    t->fd_idx = FDCOUNT_LIMIT;
  return fd;
}

int filesize(int fd) {
  struct file *file = fd_to_file(fd);
  if (file == NULL) {
    return -1;
  }
  return file_length(file);
}

struct file *fd_to_file(int fd) {
  if (fd < 0 || fd >= FDCOUNT_LIMIT) {
    return NULL;
  }

  struct thread *t = thread_current();
  struct file **fdt = t->fd_table;

  struct file *file = fdt[fd];
  return file;
}

int read(int fd, void *buffer, unsigned size) {
  check_address(buffer);
  uint8_t *buf = buffer;
  off_t read_count;

  if (fd == STDIN_FILENO) {  // STDIN일 때
    char key;
    for (read_count = 0; read_count < size; read_count++) {
      key = input_getc();
      *buf++ = key;
      if (key == '\0') {
        break;
      }
    }
  } else if (fd == STDOUT_FILENO) {  // STDOUT일 때
    return -1;
  } else {
    struct file *filep = fd_to_file(fd);  // fd에 해당하는 file
    if (filep == NULL) { // 파일을 읽을 수 없는 경우
      return -1;
    }

    // exclusive read & write
    lock_acquire(inode_get_lock(file_get_inode(filep))); 
    read_count = file_read(filep, buffer, size);
    lock_release(inode_get_lock(file_get_inode(filep)));
  }

  return read_count;
}

int write(int fd, const void *buffer, unsigned size) {
  check_address(buffer);
  int read_count;

  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    read_count = size;
  } else if (fd == STDIN_FILENO) {
    return 0;
  } else {
    struct file *filep = fd_to_file(fd);
    if (filep == NULL) {
      return 0;
    }

    // exclusive read & write
    lock_acquire(inode_get_lock(file_get_inode(filep)));
    read_count = file_write(filep, buffer, size);
    lock_release(inode_get_lock(file_get_inode(filep)));
  }
  return read_count;
}

void seek(int fd, unsigned position) {
  if (fd < 2) {
    return;
  }
  struct file *file = fd_to_file(fd);
  // check_address(file);
  if (file == NULL) {
    return;
  }
  file_seek(file, position);
}

unsigned tell(int fd) {
  if (fd < 2) {
    return;
  }
  struct file *file = fd_to_file(fd);
  // check_address(file);
  if (file == NULL) {
    return;
  }
  return file_tell(file);
}

void close(int fd) {
  struct file *file = fd_to_file(fd);
  if (file == NULL) {
    return;
  }
  delete_file_from_fd_table(fd);
  file_close(file);
}

void delete_file_from_fd_table(int fd) {
	struct thread *t = thread_current();
  if (fd < 0 || fd >= FDCOUNT_LIMIT)
    return;
	struct file **fdt = t->fd_table;

  fdt[fd] = NULL;
}

// !SECTION - File based System Call
/* Extra */
int dup2(int oldfd, int newfd) { return 0; }
// !SECTION - Project 2 USERPROG SYSTEM CALL