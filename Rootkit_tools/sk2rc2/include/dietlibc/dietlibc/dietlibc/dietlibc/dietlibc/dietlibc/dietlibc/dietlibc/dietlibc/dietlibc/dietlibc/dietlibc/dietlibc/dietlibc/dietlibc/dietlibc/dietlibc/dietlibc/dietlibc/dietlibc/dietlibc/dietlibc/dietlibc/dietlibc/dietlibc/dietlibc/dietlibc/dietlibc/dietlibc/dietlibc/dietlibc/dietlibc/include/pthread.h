#ifndef _PTHREAD_H
#define _PTHREAD_H 1

#include <sched.h>
#include <signal.h>
#include <setjmp.h>

#define PTHREAD_STACK_SIZE	16384

#define PTHREAD_THREADS_MAX	128

#define MAX_SPIN_COUNT		50
#define SPIN_SLEEP_DURATION	2000001

#define PTHREAD_KEYS_MAX	7
#define PTHREAD_DESTRUCTOR_ITERATIONS 10

typedef struct _pthread_descr_struct *_pthread_descr;
typedef int pthread_t;

/* Fast locks */
#ifdef __parisc__
#define PTHREAD_SPIN_LOCKED 0
#define PTHREAD_SPIN_UNLOCKED 1
#else
#define PTHREAD_SPIN_LOCKED 1
#define PTHREAD_SPIN_UNLOCKED 0
#endif
struct _pthread_fastlock {
  int __spinlock;
};

/* Mutexes */
typedef struct {
  struct _pthread_fastlock lock;
  _pthread_descr owner;
  int kind;
  unsigned int count;
} pthread_mutex_t;

enum {
  PTHREAD_MUTEX_FAST_NP,
  PTHREAD_MUTEX_RECURSIVE_NP,
  PTHREAD_MUTEX_ERRORCHECK_NP,
};

enum
{
  PTHREAD_PROCESS_PRIVATE,
#define PTHREAD_PROCESS_PRIVATE PTHREAD_PROCESS_PRIVATE
  PTHREAD_PROCESS_SHARED
#define PTHREAD_PROCESS_SHARED PTHREAD_PROCESS_SHARED
};

#define PTHREAD_MUTEX_INITIALIZER \
{{PTHREAD_SPIN_UNLOCKED}, 0, PTHREAD_MUTEX_FAST_NP, 0}

#define PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP \
{{PTHREAD_SPIN_UNLOCKED}, 0, PTHREAD_MUTEX_RECURSIVE_NP, 0}

#define PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP \
{{PTHREAD_SPIN_UNLOCKED}, 0, PTHREAD_MUTEX_ERRORCHECK_NP, 0}

typedef struct {
  int __mutexkind;
} pthread_mutexattr_t;

int pthread_mutexattr_init(pthread_mutexattr_t *attr);
int pthread_mutexattr_destroy(pthread_mutexattr_t *attr);

int pthread_mutexattr_getkind_np(const pthread_mutexattr_t *attr, int *kind);
int pthread_mutexattr_setkind_np(pthread_mutexattr_t *attr, int kind);

int pthread_mutex_init(pthread_mutex_t *mutex,
		const pthread_mutexattr_t *mutexattr);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
int pthread_mutex_destroy(pthread_mutex_t *mutex);

/* Conditions */
typedef void* pthread_condattr_t;

typedef struct {
  struct _pthread_fastlock lock;
  _pthread_descr wait_chain;
} pthread_cond_t;

#define PTHREAD_COND_INITIALIZER \
{{PTHREAD_SPIN_UNLOCKED},0}

int pthread_cond_init(pthread_cond_t *cond, pthread_condattr_t *cond_attr);
int pthread_cond_destroy(pthread_cond_t *cond);
int pthread_cond_signal(pthread_cond_t *cond);
int pthread_cond_broadcast(pthread_cond_t *cond);
int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
			   const struct timespec *abstime);
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);

/* only for completeness (always return NULL) */
int pthread_condattr_init(pthread_condattr_t *attr);
int pthread_condattr_destroy(pthread_condattr_t *attr);
int pthread_condattr_getpshared(const pthread_condattr_t *attr, int *pshared);
int pthread_condattr_setpshared(pthread_condattr_t *attr, int pshared);

/* thread specific variables */
typedef unsigned int pthread_key_t;

int pthread_key_create(pthread_key_t *key, void (*destructor)(const void*));
int pthread_key_delete(pthread_key_t key);
int pthread_setspecific(pthread_key_t key, const void *value);
const void *pthread_getspecific(pthread_key_t key);


/* Attributes for threads.  */
typedef struct
{
  int		__detachstate;
  int		__schedpolicy;
  struct sched_param	__schedparam;
  int		__inheritsched;
  int		__scope;
  void *	__stackaddr;
  unsigned long __stacksize;
} pthread_attr_t;

enum
{
  PTHREAD_CREATE_JOINABLE,
#define PTHREAD_CREATE_JOINABLE PTHREAD_CREATE_JOINABLE
  PTHREAD_CREATE_DETACHED
#define PTHREAD_CREATE_DETACHED PTHREAD_CREATE_DETACHED
};

enum
{
  PTHREAD_EXPLICIT_SCHED,
#define PTHREAD_EXPLICIT_SCHED PTHREAD_EXPLICIT_SCHED
  PTHREAD_INHERIT_SCHED
#define PTHREAD_INHERIT_SCHED PTHREAD_INHERIT_SCHED
};

enum	/* for completeness */
{
  PTHREAD_SCOPE_SYSTEM,
#define PTHREAD_SCOPE_SYSTEM PTHREAD_SCOPE_SYSTEM
  PTHREAD_SCOPE_PROCESS
#define PTHREAD_SCOPE_PROCESS PTHREAD_SCOPE_PROCESS
};

int pthread_attr_init(pthread_attr_t *attr);
int pthread_attr_destroy(pthread_attr_t *attr);

int pthread_attr_setdetachstate(pthread_attr_t *attr, int detachstate);
int pthread_attr_getdetachstate(const pthread_attr_t *attr, int *detachstate);

int pthread_attr_setschedpolicy(pthread_attr_t *attr, int policy);
int pthread_attr_getschedpolicy(const pthread_attr_t *attr, int *policy);

int pthread_attr_setschedparam(pthread_attr_t *attr,
				const struct sched_param *param);
int pthread_attr_getschedparam(const pthread_attr_t *attr,
				struct sched_param *param);

int pthread_attr_setinheritsched(pthread_attr_t *attr, int inherit);
int pthread_attr_getinheritsched(const pthread_attr_t *attr, int *inherit);

int pthread_attr_setscope(pthread_attr_t *attr, int scope);
int pthread_attr_getscope(const pthread_attr_t *attr, int *scope);

int pthread_attr_setstackaddr(pthread_attr_t *attr, void *stack);
int pthread_attr_getstackaddr(pthread_attr_t *attr, void **stack);

int pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize);
int pthread_attr_getstacksize(pthread_attr_t *attr, size_t *stacksize);

int pthread_setschedparam(pthread_t target_thread, int policy,
			  const struct sched_param *param);
int pthread_getschedparam(pthread_t target_thread, int *policy,
			  struct sched_param *param);

/* ONCE */
typedef int pthread_once_t;
#define PTHREAD_ONCE_INIT	0

int __pthread_once(pthread_once_t* once_control, void (*init_routine)(void));
int pthread_once(pthread_once_t* once_control, void (*init_routine)(void));

/* CANCEL */

enum {
  PTHREAD_CANCEL_ENABLE,
#define PTHREAD_CANCEL_ENABLE PTHREAD_CANCEL_ENABLE
  PTHREAD_CANCEL_DISABLE,
#define PTHREAD_CANCEL_DISABLE PTHREAD_CANCEL_DISABLE
};

enum {
  PTHREAD_CANCEL_ASYNCHRONOUS,
#define PTHREAD_CANCEL_ASYNCHRONOUS PTHREAD_CANCEL_ASYNCHRONOUS
  PTHREAD_CANCEL_DEFERRED,
#define PTHREAD_CANCEL_DEFERRED PTHREAD_CANCEL_DEFERRED
};

#define PTHREAD_CANCELED ((void *) -1)

int pthread_cancel(pthread_t thread);
int pthread_setcancelstate(int state, int *oldstate);

int pthread_setcanceltype(int type, int *oldtype);

void pthread_testcancel(void);

/* CLEANUP */

void pthread_cleanup_push(void (*routine)(void*), void *arg);
void pthread_cleanup_pop (int execute);

void pthread_cleanup_push_defer_np(void (*routine)(void *), void *arg);
void pthread_cleanup_pop_restore_np(int execute);

/* FORK */

pid_t pthread_atfork(void (*prepare)(void), void (*parent)(void),
		     void (*child)(void));

/* THREADS */
int pthread_create (pthread_t *__thread,
		const pthread_attr_t *__attr,
		void *(*__start_routine) (void *),
		void *__arg);

void pthread_exit (void *__retval) __attribute__ ((__noreturn__));

int pthread_join (pthread_t __th, void **__thread_return);

int pthread_detach (pthread_t __th);

pthread_t pthread_self (void);
int pthread_equal (pthread_t __thread1, pthread_t __thread2);

#define pthread_sigmask(h,n,o) sigprocmask((h),(n),(o))

#endif
