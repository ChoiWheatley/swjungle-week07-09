#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#ifdef VM
#include "vm/vm.h"
#endif


/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */
	int nice;                           /* 다른 스레드에게 얼마나 CPU time을 퍼줄 것인지 */
  fixed_point recent_cpu;             /* 스레드가 CPU time을 얼마나 점유하고 있는지 */
	
	int64_t local_tick; 								/* `timer_sleep`에서 저장할 로컬 틱 */
	struct lock *wait_on_lock;				  /* 내가 기다리고 있는 lock */
	
	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element used for ready list OR waiters list */
	
	struct list donation_list;					/* 내가 가진 lock들의 waiter들 중 최대 priority를 가진 스레드들의 d_elem 연결리스트*/
	struct list_elem d_elem; 						/* donation 리스트의 원소 */

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);

/** SECTION - Additional Decl */
void thread_sleep(int64_t ticks);
void thread_wakeup(); // sleep_list에서 자기 차례가 되면 ready_list로 unblock해서 list_push_back 함수

struct thread *get_thread_elem(const struct list_elem *elem);
struct thread *get_thread_d_elem(const struct list_elem *elem);

int get_priority(struct thread *target);
int get_nice(struct thread *target);
void set_nice(struct thread *target, int val);
int get_recent_cpu(struct thread *target);
void update_recent_cpu(struct thread *target);
void update_load_avg();

int get_priority_mlfqs(struct thread *target);

bool tick_ascend(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
bool priority_dsc(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
bool priority_asc(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
bool priority_dsc_d(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
bool priority_asc_d(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
bool origin_priority_dsc(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
bool origin_priority_asc(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
bool origin_priority_dsc_d(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
bool origin_priority_asc_d(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
/** !SECTION - Additional Decl */

/** SECTION - Fixed Point Arithmetic Operations */

/// @brief 17.14 고정소수점 실수
typedef int32_t fixed_point;

#define P 17
#define Q (31 - P)
#define F (1 << Q)
#define FIXED_POINT(n) ((n) * (F))
#define INT32_T(x) ((x) / (F))
#define INT32_T_RND(x) \
  ((x) >= 0) ? ((x) + (F) / 2) / (F) : ((x) - (F) / 2) / (F)
#define FXP_ADD(x, y) ((x) + (y))
#define FXP_ADD_INT(x, n) ((x) + FIXED_POINT(n))
#define FXP_SUB(x, y) ((x) - (y))
#define FXP_SUB_INT(x, n) ((x)-FIXED_POINT(n))
#define FXP_MUL(x, y) (((int64_t)(x)) * (y) / F)
#define FXP_MUL_INT(x, n) ((x) * (n))
#define FXP_DIV(x, y) (((int64_t)(x)) * F / (y))
#define FXP_DIV_INT(x, n) ((x) / (n))

inline fixed_point to_fixed_point(int32_t n) { return FIXED_POINT(n); }
inline int32_t to_int32_t(fixed_point x) { return INT32_T(x); }
inline int32_t to_int32_t_rnd(fixed_point x) { return INT32_T_RND(x); }
inline fixed_point add(fixed_point x, fixed_point y) { return FXP_ADD(x, y); }
inline fixed_point add_int(fixed_point x, int32_t n) { return FXP_ADD_INT(x, n); }
inline fixed_point sub(fixed_point x, fixed_point y) { return FXP_SUB(x, y); }
inline fixed_point sub_int(fixed_point x, int32_t n) { return FXP_SUB_INT(x, n); }
inline fixed_point mul(fixed_point x, fixed_point y) { return FXP_MUL(x, y); }
inline fixed_point mul_int(fixed_point x, int32_t n) { return FXP_MUL_INT(x, n); }
inline fixed_point div(fixed_point x, fixed_point y) { return FXP_DIV(x, y); }
inline fixed_point div_int(fixed_point x, int32_t n) { return FXP_DIV_INT(x, n); }

/** !SECTION - Fixed Point Arithmetic Operations */

#endif /* threads/thread.h */
