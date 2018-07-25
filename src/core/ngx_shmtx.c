
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (NGX_HAVE_ATOMIC_OPS)


static void ngx_shmtx_wakeup(ngx_shmtx_t *mtx);

/*
 mtx：	要创建的锁
 addr：	创建锁时，内部用到的原子变量，由于锁是多个进程之间共享的，所以 addr 指向的内存都是在共享内存进行分配的。
 name：	没有意义，使用文件锁实现互斥锁时才会用到该变量
*/
ngx_int_t
ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr, u_char *name)
{
	//保存原子变量的地址，由于锁时多个进程之间共享的，那么原子变量一般在共享内存进行分配
    // 上面的addr就表示在共享内存中分配的内存地址，至于共享内存的分配下次再说
    mtx->lock = &addr->lock;

	// 在不支持信号量时，spin只表示锁的自旋次数，那么该值为0或负数表示不进行自旋，直接让出cpu，
    // 当支持信号量时，它为-1表示，不要使用信号量将进程置于睡眠状态，这对 nginx 的性能至关重要。
    if (mtx->spin == (ngx_uint_t) -1) {	
        return NGX_OK;
    }

    mtx->spin = 2048;	 // 默认自旋次数是2048

#if (NGX_HAVE_POSIX_SEM)

    mtx->wait = &addr->wait;

	//初始化信号量，第二个参数1表示，信号量使用在多进程环境中，第三个参数0表示信号量的初始值
	//当信号量的值小于等于0时，尝试等待信号量会阻塞
	//当信号量大于0时，尝试等待信号量会成功，并把信号量的值减一
    if (sem_init(&mtx->sem, 1, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno, "sem_init() failed");
    } else {
        mtx->semaphore = 1;
    }

#endif

    return NGX_OK;
}


/*
  基于原子操作实现的互斥锁，在销毁时，如果支持信号量，则需要销毁创建的信号量
*/
void
ngx_shmtx_destroy(ngx_shmtx_t *mtx)
{
#if (NGX_HAVE_POSIX_SEM)

    if (mtx->semaphore) {
        if (sem_destroy(&mtx->sem) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno, "sem_destroy() failed");
        }
    }

#endif
}


ngx_uint_t
ngx_shmtx_trylock(ngx_shmtx_t *mtx)
{
    return (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid));
}


void
ngx_shmtx_lock(ngx_shmtx_t *mtx)
{
    ngx_uint_t         i, n;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx lock");

    for ( ;; ) {

		//尝试获取锁，如果*mtx->lock为0，表示锁未被其他进程占有，
        //这时调用ngx_atomic_cmp_set这个原子操作尝试将*mtx->lock设置为进程id，如果设置成功，则表示加锁成功，否则失败。
        //注意：由于在多进程环境下执行，*mtx->lock == 0 为真时，并不能确保ngx_atomic_cmp_set函数执行成功
        if (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)) {
            return;
        }

		//获取锁失败了，这时候判断cpu的数目，如果数目大于1，则先自旋一段时间，然后再让出cpu
        //如果cpu数目为1，则没必要进行自旋了，应该直接让出cpu给其他进程执行。
        if (ngx_ncpu > 1) {

            for (n = 1; n < mtx->spin; n <<= 1) {	//指数避让

                for (i = 0; i < n; i++) {
					//ngx_cpu_pause()函数并不是真的将程序暂停，而是为了提升循环等待时的性能，并且可以降低系统功耗。
                    //实现它时往往是一个指令： `__asm__`("pause")
                    ngx_cpu_pause();
                }

				//再次尝试获取锁
                if (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)) {
                    return;
                }
            }
        }

#if (NGX_HAVE_POSIX_SEM)

		//上面自旋次数已经达到，依然没有获取锁，将进程在信号量上挂起，等待其他进程释放锁后再唤醒。
        if (mtx->semaphore) {	// 使用信号量进行阻塞，即上面设置创建锁时，mtx的spin成员变量的值不是-1
            (void) ngx_atomic_fetch_add(mtx->wait, 1);	//当前在该信号量上等待的进程数目加一

			// 尝试获取一次锁，如果获取成功，将等待的进程数目减一，然后返回
            if (*mtx->lock == 0 && ngx_atomic_cmp_set(mtx->lock, 0, ngx_pid)) {
                (void) ngx_atomic_fetch_add(mtx->wait, -1);
                return;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx wait %uA", *mtx->wait);

			//在信号量上进行等待，这时进程将会睡眠，直到其他进程释放了锁
            while (sem_wait(&mtx->sem) == -1) {
                ngx_err_t  err;

                err = ngx_errno;

                if (err != NGX_EINTR) {
                    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err, "sem_wait() failed while waiting on shmtx");
                    break;
                }
            }

            ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx awoke");

			//其他进程释放锁了，所以继续回到循环的开始，尝试再次获取锁，注意它并不会执行下面ngx_sched_yield()函数
            continue;
        }

#endif

		//在没有获取到锁，且不使用信号量时，会执行到这里，
		//一般通过 sched_yield 函数实现，让调度器暂时将进程切出，让其他进程执行。
        //在其它进程执行后有可能释放锁，那么下次调度到本进程时，则有可能获取成功。
        ngx_sched_yield();
    }
}


void
ngx_shmtx_unlock(ngx_shmtx_t *mtx)
{
    if (mtx->spin != (ngx_uint_t) -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx unlock");
    }

	//释放锁，将原子变量设为0，同时唤醒在信号量上等待的进程
    if (ngx_atomic_cmp_set(mtx->lock, ngx_pid, 0)) {
        ngx_shmtx_wakeup(mtx);
    }
}


ngx_uint_t
ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid)
{
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx forced unlock");

    if (ngx_atomic_cmp_set(mtx->lock, pid, 0)) {
        ngx_shmtx_wakeup(mtx);
        return 1;
    }

    return 0;
}


static void
ngx_shmtx_wakeup(ngx_shmtx_t *mtx)
{
#if (NGX_HAVE_POSIX_SEM)
    ngx_atomic_uint_t  wait;

    if (!mtx->semaphore) {	//如果没有使用信号量，直接返回
        return;
    }

    for ( ;; ) {

        wait = *mtx->wait;

        if ((ngx_atomic_int_t) wait <= 0) {	//wait小于等于0，说明当前没有进程在信号量上睡眠
            return;
        }

        if (ngx_atomic_cmp_set(mtx->wait, wait, wait - 1)) {
            break;
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0, "shmtx wake %uA", wait);

	//将信号量的值加1
    if (sem_post(&mtx->sem) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno, "sem_post() failed while wake shmtx");
    }

#endif
}


#else


/*
 mtx：	要创建的锁
 addr：	没有意义，使用原子操作实现互斥锁时才会用到该变量
 name：	文件锁使用的文件
*/
ngx_int_t
ngx_shmtx_create(ngx_shmtx_t *mtx, ngx_shmtx_sh_t *addr, u_char *name)
{
    if (mtx->name) {	// mtx->name不为NULL，说明它之前已经创建过锁

        if (ngx_strcmp(name, mtx->name) == 0) {	// 之前创建过锁，且与这次创建锁的文件相同，则不需要创建，直接返回
            mtx->name = name;
            return NGX_OK;
        }

        ngx_shmtx_destroy(mtx);	// 销毁之前创建到锁，其实就是关闭之前创建锁时打开的文件。
    }

    mtx->fd = ngx_open_file(name, NGX_FILE_RDWR, NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS);

    if (mtx->fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, ngx_cycle->log, ngx_errno, ngx_open_file_n " \"%s\" failed", name);
        return NGX_ERROR;
    }

	//使用锁时只需要该文件在内核中的inode信息，所以将该文件删掉
    if (ngx_delete_file(name) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno, ngx_delete_file_n " \"%s\" failed", name);
    }

    mtx->name = name;

    return NGX_OK;
}

/*
 基于文件锁实现的互斥锁，在销毁时，需要关闭打开的文件
*/
void
ngx_shmtx_destroy(ngx_shmtx_t *mtx)
{
    if (ngx_close_file(mtx->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, ngx_errno, ngx_close_file_n " \"%s\" failed", mtx->name);
    }
}


ngx_uint_t
ngx_shmtx_trylock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_trylock_fd(mtx->fd);

    if (err == 0) {	// 获取锁成功，返回1
        return 1;
    }

    if (err == NGX_EAGAIN) {	// 获取锁失败，如果错误码是 NGX_EAGAIN，表示文件锁正被其他进程占用，返回0
        return 0;
    }

#if __osf__ /* Tru64 UNIX */

    if (err == NGX_EACCES) {
        return 0;
    }

#endif

	// 其他错误都不应该发生，打印错误日志
    ngx_log_abort(err, ngx_trylock_fd_n " %s failed", mtx->name);

    return 0;
}


/*
 基于文件锁实现的互斥锁，在加锁时，如果该文件锁正被其他进程占有，则会导致进程阻塞。
*/
void
ngx_shmtx_lock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_lock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    ngx_log_abort(err, ngx_lock_fd_n " %s failed", mtx->name);
}


void
ngx_shmtx_unlock(ngx_shmtx_t *mtx)
{
    ngx_err_t  err;

    err = ngx_unlock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    ngx_log_abort(err, ngx_unlock_fd_n " %s failed", mtx->name);
}


/*
基于文件锁实现的互斥锁，在进程结束时，系统会关闭该进程所有未关闭的文件描述符，
从而实现自动销毁该互斥锁
*/
ngx_uint_t
ngx_shmtx_force_unlock(ngx_shmtx_t *mtx, ngx_pid_t pid)
{
    return 0;
}

#endif
