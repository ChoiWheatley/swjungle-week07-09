#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

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

void halt (void);
void exit (int status);
pid_t fork (const char *thread_name);
int exec (const char *file);
int wait (pid_t pid);

bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

int dup2 (int oldfd, int newfd);

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {

	// TODO: Your implementation goes here.
	switch (f->R.rax) {
		case SYS_HALT:
			halt();
		case SYS_EXIT:
			exit(f->R.rdi);
		case SYS_FORK:
			fork(f->R.rdi);
		case SYS_EXEC:
			exec(f->R.rdi);
		case SYS_WAIT:
			wait(f->R.rdi);
		case SYS_CREATE:
			create(f->R.rdi, f->R.rsi);
		case SYS_REMOVE:
			remove(f->R.rdi);
		case SYS_OPEN:
			open(f->R.rdi);
		case SYS_FILESIZE:
			filesize(f->R.rdi);
		case SYS_READ:
			read(f->R.rdi, f->R.rsi, f->R.rdx);
		case SYS_WRITE:
			write(f->R.rdi, f->R.rsi, f->R.rdx);
		case SYS_SEEK:
			seek(f->R.rdi,f->R.rsi);
		case SYS_TELL:
			tell(f->R.rdi);
		case SYS_CLOSE:
			close(f->R.rdi);
	
	}
	printf ("system call!\n");
	thread_exit ();
}

//SECTION - Project 2 USERPROG SYSTEM CALL
//SECTION - Process based System Call
void halt (void) {

}

void exit (int status) {

}

pid_t fork (const char *thread_name) {

}

int exec (const char *file) {

}

int wait (pid_t pid) {

}
//!SECTION - Process based System Call
//SECTION - File based System Call
bool create (const char *file, unsigned initial_size) {

}

bool remove (const char *file) {

}

int open (const char *file) {

}

int filesize (int fd) {

}

int read (int fd, void *buffer, unsigned size) {

}

int write (int fd, const void *buffer, unsigned size) {

}

void seek (int fd, unsigned position) {

}

unsigned tell (int fd) {

}

void close (int fd) {

}
//!SECTION - File based System Call
/* Extra */
int dup2 (int oldfd, int newfd) {
	return 0
}
//!SECTION - Project 2 USERPROG SYSTEM CALL