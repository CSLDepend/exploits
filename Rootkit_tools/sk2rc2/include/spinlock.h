/*
 * $Id: SMP races handling. It's far to be complete, but
 *	it seems to be step in the right way
 *	[ unused at this time, smp not implemented yet ]
 */

#ifndef SPINLOCK_H
#define SPINLOCK_H

#define lock_t unsigned long
#define	LOCK_UNLOCKED	0
#define	LOCK_LOCKED	1

/* yep, this could be done by gcc too, but we all know that gcc
   is one big mess, _never_ trust him */
#define	spin_lock(lock)		\
do {				\
	__asm__ __volatile__ (	\
		"2:\n\t"	\
		"lock\n\t"	\
		"btsl $0,%0\n\t"\
		"jnc	3f\n\t"	\
		"1:\n\t"	\
		"testl $1,%0\n\t"\
		"jz	2b\n\t"	\
		"jmp	1b\n\t"	\
		"3:\n\t"	\
		: "=m" (lock)	\
	);			\
} while(0);

/* this will unlock, unless already unlocked; this
   should avoid propagating bugs in suckit itself ;) */
#define spin_unlock(lock)	\
do {				\
	__asm__ __volatile__ (	\
		"lock\n\t"	\
		"btrl $0,%0\n\t" \
		: "=m" (lock)	\
	);			\
} while(0);

#define spin_islocked(x) x
extern	lock_t kernel_lock;

static inline void lock_kernel()
{
	spin_lock(kernel_lock);
}

static inline void unlock_kernel()
{
	spin_unlock(kernel_lock);
}

#endif
