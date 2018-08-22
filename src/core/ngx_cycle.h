
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

struct ngx_shm_zone_s {
    void                     *data;		//共享内存特定数据,由申请此共享内存的模块设置	
    ngx_shm_t                 shm;	
    ngx_shm_zone_init_pt      init;		//共享内存特定初始化函数,由申请此共享内存的模块设置
    void                     *tag;		//共享内存标签，用于标识该共享内存属于哪个模块
    void                     *sync;
    ngx_uint_t                noreuse;	//(重新加载配置时)共享内存是否可以被重用,由申请此共享内存的模块设置
};


//A cycle object stores the nginx runtime context created from a specific configuration. 
struct ngx_cycle_s {
	//Array of core module configurations. 
	//The configurations are created and filled during reading of nginx configuration files.
    void                  ****conf_ctx;	
    ngx_pool_t               *pool;		//Cycle pool. Created for each new cycle.

	//Cycle log. Initially inherited from the old cycle, it is set to point to new_log after the configuration is read. 
	//日志模块中提供了生成基本ngx_log_t日志对象的功能，这里的log实际上是在还没有执行ngx_init_cycle方法前，也就是还没有解析配置前，
	//如果有信需要输出到日志，就会暂时使用log对象，它会输出到屏幕。在ngx_init_cycle方法执行后，将会根据nginx.conf配置文件中的配置项，
	//构造出正确的日志文件，此时会对log重新赋值
    ngx_log_t                *log;		
	//Cycle log, created by the configuration. It's affected by the root-scope error_log directive. 
	//由nginx.conf配置文件读取到日志文件路径后，将开始初始化error_log日志文件，由于log对象还在用于输出日志到屏幕，
	//这时会用new_log对象暂时性的替代log日志，待初始化成功后，会用new_log的地址覆盖上面的log指针
    ngx_log_t                 new_log;	

	//XXX:表明我们在error_log指令中使用了stderr，因此我们不能将stderr进行重定向(ngx_log_redirect_stderr)		
    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */

	//Array for mapping file descriptors to nginx connections. This mapping is used by the event modules, having the 
	//NGX_USE_FD_EVENT flag (currently, it's poll and devpoll).
    ngx_connection_t        **files;
	//List and number of currently available connections. If no connections are available, an nginx worker refuses to
	//accept new clients or connect to upstream servers.
    ngx_connection_t         *free_connections;	
    ngx_uint_t                free_connection_n;//可用连接池中连接的总数

	//Array of modules of type ngx_module_t, both static and dynamic, loaded by the current configuration.
	//XXX: 为什么这里要通过拷贝一份成指针数组，使用原始的ngx_modules数组不行么？
    ngx_module_t            **modules;		
    ngx_uint_t                modules_n;
    ngx_uint_t                modules_used;		//prevent loading of additional modules 

    ngx_queue_t               reusable_connections_queue;	//ngx_connection_t类型的双向链表容器，表示可重复使用的连接的队列
    ngx_uint_t                reusable_connections_n;

	//Array of listening objects of type ngx_listening_t. Listening objects are normally added by the listen directive
	//of different modules which call the ngx_create_listening() function. Listen sockets are created based on the 
	//listening objects.
    ngx_array_t               listening;	
	
	//Array of paths of type ngx_path_t. 
	//Paths are added by calling the function ngx_add_path() from modules which are going to operate on certain directories. 
	//These directories are created by nginx after reading configuration, if missing. Moreover, two handlers can be added for each path:
	//		path loader — Executes only once in 60 seconds after starting or reloading nginx. Normally, the loader reads the directory 
	//			and stores data in nginx shared memory. The handler is called from the dedicated nginx process “nginx cache loader”.
	//		path manager — Executes periodically. Normally, the manager removes old files from the directory and updates nginx memory to
	//			reflect the changes. The handler is called from the dedicated “nginx cache manager” process.
	ngx_array_t               paths;		//ngx_path_t*类型的动态数组，保存着Nginx所有要操作的所有目录。如果有目录不存在，而创建目录失败会导致Nginx启动失败。例如，上传文件的临时目录也在pathes中，如果没有权限创建，则会导致Nginx无法启动

    ngx_array_t               config_dump;			//ngx_conf_dump_t类型的数组
    ngx_rbtree_t              config_dump_rbtree;	
    ngx_rbtree_node_t         config_dump_sentinel;

	//List of open file objects of type ngx_open_file_t, which are created by calling the function ngx_conf_open_file(). 
	//Currently, nginx uses this kind of open files for logging. After reading the configuration, nginx opens all files 
	//in the open_files list and stores each file descriptor in the object's fd field. The files are opened in append 
	//mode and are created if missing. The files in the list are reopened by nginx workers upon receiving the reopen 
	//signal (most often USR1). In this case the descriptor in the fd field is changed to a new value.
    ngx_list_t                open_files;
	
	//List of shared memory zones, each added by calling the ngx_shared_memory_add() function. Shared zones are mapped
	//to the same address range in all nginx processes and are used to share common data, for example the HTTP cache 
	//in-memory tree.
    ngx_list_t                shared_memory;	

    ngx_uint_t                connection_n;	//当前进程中所有连接对象的总数，与connections成员配合使用
    ngx_uint_t                files_n;		//与上面的files成员配合使用，指出files数组里元素的总数

    ngx_connection_t         *connections;	//Array of connections of type ngx_connection_t, created by the event module while initializing each nginx worker. The worker_connections directive in the nginx configuration sets the number of connections connection_n. //预分配的connection_n个连接。每个连接所需要的读/写事件都以相同的数组序号对应着read_events、write_events读/写事件数组，相同序号下这3个数组中的元素是配合使用的
    ngx_event_t              *read_events;	//预分配的connection_n个读事件
    ngx_event_t              *write_events;	//预分配的connection_n个写事件

    ngx_cycle_t              *old_cycle;	//旧的ngx_cycle_t对象用于引用上一个ngx_cycle_t对象中的成员。例如，ngx_init_cycle方法，在启动初期，需要建立一个临时的ngx_cycle_t对象保存一些变量，再调用ngx_init_cycle方法时就可以把旧的ngx_cycle_t对象传递进去，而这时old_cycle对象就会保存这个前期的ngx_cycle_t对象

    ngx_str_t                 conf_file;	//配置文件(一般是nginx.conf)的绝对路径
    ngx_str_t                 conf_param;	//Nginx处理配置文件时需要特殊处理的命名携带的参数，一般是-g选项携带的参数
    ngx_str_t                 conf_prefix;	//Nginx配置文件路径的前缀
    ngx_str_t                 prefix;		//Nginx安装目录的路径的前缀
    ngx_str_t                 lock_file;	//用于进程间同步的文件锁名称
    ngx_str_t                 hostname;		//使用gethostname系统调用得到的主机名
};


typedef struct {
    ngx_flag_t                daemon;	//是否以守护进程的方式运行Nginx。守护进程是脱离终端并且在后台允许的进程
    ngx_flag_t                master;	//是否以master/worker方式工作。如果关闭了master_process工作方式，就不会fork出worker子进程来处理请求，而是用master进程自身来处理请求

    ngx_msec_t                timer_resolution;	//系统调用gettimeofday的执行频率。默认情况下，每次内核的事件调用(如epoll)返回时，都会执行一次getimeofday，实现用内核时钟来更新Nginx中的缓存时钟，若设置timer_resolution则定期更新Nginx中的缓存时钟           
    ngx_msec_t                shutdown_timeout;	

    ngx_int_t                 worker_processes;	//worker进程的数目
    ngx_int_t                 debug_points;		//Nginx在一些关键的错误逻辑中设置了调试点。如果设置了debug_points为NGX_DEBUG_POINTS_STOP，那么Nginx执行到这些调试点时就会发出SIGSTOP信号以用于调试，如果设置了debug_points为NGX_DEBUG_POINTS_ABORT，那么Nginx执行到这些调试点时就会产生一个coredump文件，可以使用gdb来查看Nginx当时的各种信息

    ngx_int_t                 rlimit_nofile;	//每个工作进程的打开文件数的最大值限制(RLIMIT_NOFILE)	
    off_t                     rlimit_core;		//coredump(核心转储)文件的最大大小。在Linux系统中，当进程发生错误或收到信号而终止时，系统会将进程执行时的内存内容(核心映像)写入一个文件(core文件)，以作调试之用，这就是所谓的核心转储(core dump)

    int                       priority;	//指定Nginx worker进程的nice优先级

    ngx_uint_t                cpu_affinity_auto;
    ngx_uint_t                cpu_affinity_n;	//cpu_affinity数组元素个数
    ngx_cpuset_t             *cpu_affinity;		//uint64_t类型的数组，每个元素表示一个工作进程的CPU亲和性掩码

    char                     *username;	//用户名(work进程)
    ngx_uid_t                 user;		//用户UID(work进程)
    ngx_gid_t                 group;	//用户GID(work进程)

    ngx_str_t                 working_directory;	//指定进程当前工作目录
    ngx_str_t                 lock_file;			//lock文件的路径

    ngx_str_t                 pid;		//保存master进程ID的pid文件存放路径
    ngx_str_t                 oldpid;	//NGX_PID_PATH+NGX_OLDPID_EXT  热升级nginx进程的时候用

    ngx_array_t               env;			//Array of ngx_str_t, allows preserving some of the inherited variables, changing their values, or creating new environment variables.
    char                    **environment;	//存储当前运行时的环境变量

    ngx_uint_t                transparent;  /* unsigned  transparent:1; */
} ngx_core_conf_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
ngx_cpuset_t *ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name, size_t size, void *tag);
void ngx_set_shutdown_timer(ngx_cycle_t *cycle);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_dump_config;
extern ngx_uint_t             ngx_quiet_mode;


#endif /* _NGX_CYCLE_H_INCLUDED_ */
