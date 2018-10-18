#include "common.h"

#define DEBUG 0
#define direct dirent
#define KLF "L"
#define SIGNAL_STRING
#define PROC_FILLMEM         0x0001 // read statm
#define PROC_FILLCOM         0x0002 // alloc and fill in `cmdline'
#define PROC_FILLENV         0x0004 // alloc and fill in `environ'
#define PROC_FILLUSR         0x0008 // resolve user id number -> user name
#define PROC_FILLGRP         0x0010 // resolve group id number -> group name
#define PROC_FILLSTATUS      0x0020 // read status -- currently unconditional
#define PROC_FILLSTAT        0x0040 // read stat -- currently unconditional
#define PROC_FILLWCHAN       0x0080 // look up WCHAN name
#define PROC_FILLARG         0x0100 // alloc and fill in `cmdline'
#define PROC_FILLIO			 0x0200 // IO read

#define PROC_LOOSE_TASKS     0x0200 // threat threads as if they were processes

// Obsolete, consider only processes with one of the passed:
#define PROC_PID             0x1000  // process id numbers ( 0   terminated)
#define PROC_UID             0x4000  // user id numbers    ( length needed )

// it helps to give app code a few spare bits
#define PROC_SPARE_1     0x01000000
#define PROC_SPARE_2     0x02000000
#define PROC_SPARE_3     0x04000000
#define PROC_SPARE_4     0x08000000

#define STAT_FILE    "/proc/stat"
static int stat_fd = -1;
#define UPTIME_FILE  "/proc/uptime"
static int uptime_fd = -1;
#define LOADAVG_FILE "/proc/loadavg"
static int loadavg_fd = -1;
#define MEMINFO_FILE "/proc/meminfo"
static int meminfo_fd = -1;
#define VMINFO_FILE "/proc/vmstat"
static int vminfo_fd = -1;

//各种格式
//缓冲、缓冲缓冲区和命令未加入
//#define TASK_TITLE "PID\tpcpu\tmem\tpmem\t\tswap\teuser\tutime\tesize\tdssize\tppid\truser\tegroup\tcmd"
//#define TASK_line "%d\t%u\t%ld\t%f\t\t%ld\t%s\t%lld\t%ld\t%ld\t%d\t%s\t%s\t%s"
#define TASK_TITLE "PID\tcpu\t\tmem\tpmem\tswap\teuser\tesize\tdssize\tppid\truser\tread\twrite\tcmd"
#define TASK_line0 "%d\t%.2fs\t\t%ldKB\t%.4f\t%ldKB\t%s\t%ld\t%ld\t%d\t%s\t%s\t%s\t%s"
#define TASK_line1 "%d\t%.2fm\t\t%ldKB\t%.4f\t%ldKB\t%s\t%ld\t%ld\t%d\t%s\t%s\t%s\t%s"
#define SHOW_TASK0 ShowFormat(0, FormatMake(TASK_line0, task->tid, (float)task->pcpu / 100, task->vm_rss, (float)task->vm_rss / kb_main_total * 100, task->vm_size - task->vm_rss, task->euser, (unsigned long)task->vm_exe, (unsigned long)(task->vm_data + task->vm_stack), task->ppid, task->ruser, task->rchar, task->wchar, task->cmd)); \
char *_p = _buf; \
write(txt_fd, _p, strlen(_p)); \
	write(txt_fd, "\n", 1);

#define SHOW_TASK1 ShowFormat(0, FormatMake(TASK_line1, task->tid, (float)task->pcpu / 100 / 60, task->vm_rss, (float)task->vm_rss / kb_main_total * 100, task->vm_size - task->vm_rss, task->euser, (unsigned long)task->vm_exe, (unsigned long)(task->vm_data + task->vm_stack), task->ppid, task->ruser, task->rchar, task->wchar, task->cmd)); \
char *_p = _buf; \
write(txt_fd, _p, strlen(_p)); \
	write(txt_fd, "\n", 1);


#define NET_TITLE "\tReceive\tTransmit"
#define NET_line "lo:\t%s\t%s\neth0:\t%s\t%s"

#define LOADAV_line  "%s -%s\n"
#define LOADAV_line_alt  "%s\t -%s\n"
#define STATES_line1  "Tasks:\t" \
   " %3u \ttotal,\t %3u \trunning,\t %3u \tsleeping,\t %3u \tstopped,\t %3u \tzombie\t\n"
#define STATES_line2x4  "%s\t" \
   " %#5.1f%% \tuser,\t %#5.1f%% \tsystem,\t %#5.1f%% \tnice,\t %#5.1f%% \tidle\t\n"
#define STATES_line2x5  "%s\t" \
   " %#5.1f%% \tuser,\t %#5.1f%% \tsystem,\t %#5.1f%% \tnice,\t %#5.1f%% \tidle,\t %#5.1f%% \tIO-wait\t\n"
#define STATES_line2x6  "%s\t" \
   " %#4.1f%% \tus,\t %#4.1f%% \tsy,\t %#4.1f%% \tni,\t %#4.1f%% \tid,\t %#4.1f%% \twa,\t %#4.1f%% \thi,\t %#4.1f%% \tsi\t\n"
#define STATES_line2x7  "%s\t" \
   "%#5.1f%%\tus,\t%#5.1f%%\tsy,\t%#5.1f%%\tni,\t%#5.1f%%\tid,\t%#5.1f%%\twa,\t%#5.1f%%\thi,\t%#5.1f%%\tsi,\t%#5.1f%%\tst\t\n"
#ifdef CASEUP_SUMMK
#define MEMORY_line1  "Mem: \t" \
   " %8luK \ttotal,\t %8luK \tused,\t %8luK \tfree,\t %8luK \tbuffers\t\n"
#define MEMORY_line2  "Swap:\t" \
   " %8luK \ttotal,\t %8luK \tused,\t %8luK \tfree,\t %8luK \tcached\t\n"
#else
#define MEMORY_line1  "Mem: \t" \
   " %8luk \ttotal,\t %8luk \tused,\t %8luk \tfree,\t %8luk \tbuffers\t\n"
#define MEMORY_line2  "Swap:\t" \
   " %8luk \ttotal,\t %8luk \tused,\t %8luk \tfree,\t %8luk \tcached\t\n"
#endif

#define BAD_OPEN_MESSAGE					\
"Error: /proc must be mounted\n"				\
"  To mount /proc at boot you need an /etc/fstab line like:\n"	\
"      /proc   /proc   proc    defaults\n"			\
"  In the meantime, run \"mount /proc /proc -t proc\"\n"

#define P_G_SZ 20

#define CACHE_TWEAK_FACTOR 64

// Miscellaneous buffer sizes with liberal values -- mostly
// just to pinpoint source code usage/dependancies
#define SCREENMAX ( 512 + CACHE_TWEAK_FACTOR)
// the above might seem pretty stingy, until you consider that with every
// one of top's fields displayed we're talking a 160 byte column header --
// so that will provide for all fields plus a 350+ byte command line
#define WINNAMSIZ     4
#define CAPTABMAX     9
#define PFLAGSSIZ    32
#define CAPBUFSIZ    32
#define CLRBUFSIZ    64
#define GETBUFSIZ    32
#define TNYBUFSIZ    32
#define SMLBUFSIZ ( 256 + CACHE_TWEAK_FACTOR)
#define OURPATHSZ (1024 + CACHE_TWEAK_FACTOR)
#define MEDBUFSIZ (1024 + CACHE_TWEAK_FACTOR)
#define BIGBUFSIZ (2048 + CACHE_TWEAK_FACTOR)
#define USRNAMSIZ  GETBUFSIZ
#define ROWBUFSIZ  SCREENMAX + CLRBUFSIZ

#define PUTT(fmt,arg...) do { \
      char _str[ROWBUFSIZ]; \
      snprintf(_str, sizeof(_str), fmt, ## arg); \
      putp(_str); \
   } while (0)

#define FILE_TO_BUF(filename, fd) do{				\
    static int local_n;						\
    if (fd == -1 && (fd = open(filename, O_RDONLY)) == -1) {	\
	fputs(BAD_OPEN_MESSAGE, stderr);			\
	fflush(NULL);						\
	_exit(102);						\
    }								\
    lseek(fd, 0L, SEEK_SET);					\
    if ((local_n = read(fd, buf, sizeof buf - 1)) < 0) {	\
	perror(filename);					\
	fflush(NULL);						\
	_exit(103);						\
    }								\
    buf[local_n] = '\0';					\
}while(0)

#define ENTER(x) __cyg_profile_func_enter((void*)x,(void*)x)
#define LEAVE(x) __cyg_profile_func_exit((void*)x,(void*)x)

#ifdef LABEL_OFFSET
#define F(x) {#x, sizeof(#x)-1, (long)(&&case_##x-&&base)},
#else
#define F(x) {#x, sizeof(#x)-1, &&case_##x},
#endif
#define NUL  {"", 0, 0},

#define XinLN(T, X, L, N) ( {		\
	    T x = (X), *l = (L);		\
	    int i = 0, n = (N);			\
	    while (i < n && l[i] != x) i++;	\
	    i < n && l[i] == x;			\
	} )

typedef unsigned long long TIC_t;
typedef          long long SIC_t;
typedef long long KLONG;
typedef int (*QFP_t)(const void *, const void *);

typedef struct net_t {
	long long lo_bytes_receive, lo_bytes_transmit, eth0_bytes_receive, eth0_bytes_transmit;
	long long lo_packets_receive, lo_packets_transmit, eth0_packets_receive, eth0_packets_transmit;
	char lo_bytes_receive_s[20], lo_bytes_transmit_s[20], eth0_bytes_receive_s[20], eth0_bytes_transmit_s[20];
} net_t;

typedef struct proc_t {
// 1st 16 bytes
    int
        tid,		// (special)       task id, the POSIX thread ID (see also: tgid)
    	ppid;		// stat,status     pid of parent process
    unsigned
        pcpu;           // stat (special)  %CPU usage (is not filled in by readproc!!!)
    char
    	state,		// stat,status     single-char code for process state (S=sleeping)
    	pad_1,		// n/a             padding
    	pad_2,		// n/a             padding
    	pad_3;		// n/a             padding
// 2nd 16 bytes
    unsigned long long
	utime,		// stat            user-mode CPU time accumulated by process
	stime,		// stat            kernel-mode CPU time accumulated by process
// and so on...
	cutime,		// stat            cumulative utime of process and reaped children
	cstime,		// stat            cumulative stime of process and reaped children
	start_time;	// stat            start time of process -- seconds since 1-1-70
#ifdef SIGNAL_STRING
    char
	// Linux 2.1.7x and up have 64 signals. Allow 64, plus '\0' and padding.
	signal[18],	// status          mask of pending signals, per-task for readtask() but per-proc for readproc()
	blocked[18],	// status          mask of blocked signals
	sigignore[18],	// status          mask of ignored signals
	sigcatch[18],	// status          mask of caught  signals
	_sigpnd[18];	// status          mask of PER TASK pending signals
#else
    long long
	// Linux 2.1.7x and up have 64 signals.
	signal,		// status          mask of pending signals, per-task for readtask() but per-proc for readproc()
	blocked,	// status          mask of blocked signals
	sigignore,	// status          mask of ignored signals
	sigcatch,	// status          mask of caught  signals
	_sigpnd;	// status          mask of PER TASK pending signals
#endif
    unsigned long long
	start_code,	// stat            address of beginning of code segment
	end_code,	// stat            address of end of code segment
	start_stack,	// stat            address of the bottom of stack for the process
	kstk_esp,	// stat            kernel stack pointer
	kstk_eip,	// stat            kernel instruction pointer
	wchan;		// stat (special)  address of kernel wait channel proc is sleeping in
    long
	priority,	// stat            kernel scheduling priority
	nice,		// stat            standard unix nice level of process
	rss,		// stat            resident set size from /proc/#/stat (pages)
	alarm,		// stat            ?
    // the next 7 members come from /proc/#/statm
	size,		// statm           total # of pages of memory
	resident,	// statm           number of resident set (non-swapped) pages (4k)
	share,		// statm           number of pages of shared (mmap'd) memory
	trs,		// statm           text resident set size
	lrs,		// statm           shared-lib resident set size
	drs,		// statm           data resident set size
	dt;		// statm           dirty pages
    unsigned long
	vm_size,        // status          same as vsize in kb
	vm_lock,        // status          locked pages in kb
	vm_rss,         // status          same as rss in kb
	vm_data,        // status          data size
	vm_stack,       // status          stack size
	vm_exe,         // status          executable size
	vm_lib,         // status          library size (all pages, not just used ones)
	rtprio,		// stat            real-time priority
	sched,		// stat            scheduling class
	vsize,		// stat            number of pages of virtual memory ...
	rss_rlim,	// stat            resident set size limit?
	flags,		// stat            kernel flags for the process
	min_flt,	// stat            number of minor page faults since process start
	maj_flt,	// stat            number of major page faults since process start
	cmin_flt,	// stat            cumulative min_flt of process and child processes
	cmaj_flt;	// stat            cumulative maj_flt of process and child processes
    char
	**environ,	// (special)       environment string vector (/proc/#/environ)
	**cmdline;	// (special)       command line string vector (/proc/#/cmdline)
    char
	// Be compatible: Digital allows 16 and NT allows 14 ???
    	euser[P_G_SZ],	// stat(),status   effective user name
    	ruser[P_G_SZ],	// status          real user name
    	suser[P_G_SZ],	// status          saved user name
    	fuser[P_G_SZ],	// status          filesystem user name
    	rgroup[P_G_SZ],	// status          real group name
    	egroup[P_G_SZ],	// status          effective group name
    	sgroup[P_G_SZ],	// status          saved group name
    	fgroup[P_G_SZ],	// status          filesystem group name
    	cmd[16];	// stat,status     basename of executable file in call to exec(2)
    struct proc_t
	*ring,		// n/a             thread group ring
	*next;		// n/a             various library uses
    int
	pgrp,		// stat            process group id
	session,	// stat            session id
	nlwp,		// stat,status     number of threads, or 0 if no clue
	tgid,		// (special)       task group ID, the POSIX PID (see also: tid)
	tty,		// stat            full device number of controlling terminal
        euid, egid,     // stat(),status   effective
        ruid, rgid,     // status          real
        suid, sgid,     // status          saved
        fuid, fgid,     // status          fs (used for file access only)
	tpgid,		// stat            terminal process group id
	exit_signal,	// stat            might not be SIGCHLD
	processor;      // stat            current (or most recent?) CPU
	//Linux process I/O
	char	  rchar[10],	//rchar
	          wchar[10],	//wchar
			  syscr[10],	//syscr
			  syscw[10],	//syscw
			  read_bytes[10],	//read_bytes
			  write_bytes[10],	//write_bytes
			  cancelled_write_bytes[10];	//cancelled_write_bytes
} proc_t;

typedef struct PROCTAB {
	    DIR*	procfs;
		DIR*	taskdir;  // for threads
		pid_t	taskdir_user;  // for threads
		int         did_fake; // used when taskdir is missing
		int (*finder)(struct PROCTAB *__restrict const, proc_t *__restrict const);
		proc_t* (*reader)(struct PROCTAB *__restrict const, proc_t *__restrict const);
		int (*taskfinder)(struct PROCTAB *__restrict const, const proc_t *__restrict const, proc_t *__restrict const, char *__restrict const);
		proc_t* (*taskreader)(struct PROCTAB *__restrict const, const proc_t *__restrict const, proc_t *__restrict const, char *__restrict const);
		pid_t*	pids;	// pids of the procs
		uid_t*	uids;	// uids of procs
		int		nuid;	// cannot really sentinel-terminate unsigned short[]
		int         i;  // generic
		unsigned	flags;
		unsigned    u;  // generic
		void *      vp; // generic
		char        path[64];  // must hold /proc/2000222000/task/2000222000/cmdline
		unsigned pathlen;        // length of string in the above (w/o '\0')
}PROCTAB;

typedef struct RCW_t {  // the 'window' portion of an rcfile
   unsigned  sortindx;             // sort field, represented as a procflag
   int    winflags,             // 'view', 'show' and 'sort' mode flags
          maxtasks,             // user requested maximum, 0 equals all
          summclr,                      // color num used in summ info
          msgsclr,                      //        "       in msgs/pmts
          headclr,                      //        "       in cols head
          taskclr;                      //        "       in task rows
   char   winname [WINNAMSIZ],          // window name, user changeable
          fieldscur [PFLAGSSIZ];        // fields displayed and ordered
} RCW_t;

typedef struct RCF_t {  // the complete rcfile (new style)
   int    mode_altscr;          // 'A' - Alt display mode (multi task windows)
   int    mode_irixps;          // 'I' - Irix vs. Solaris mode (SMP-only)
   float  delay_time;           // 'd' or 's' - How long to sleep twixt updates
   int    win_index;            // Curwin, as index
   RCW_t  win [4];              // a 'WIN_t.rc' for each of the 4 windows
} RCF_t;

typedef struct HST_t {
   TIC_t tics;
   int   pid;
} HST_t;

typedef struct CPU_t {
   TIC_t u, n, s, i, w, x, y, z; // as represented in /proc/stat
   TIC_t u_sav, s_sav, n_sav, i_sav, w_sav, x_sav, y_sav, z_sav; // in the order of our display
   unsigned id;  // the CPU ID number
} CPU_t;

typedef struct mem_table_struct {
  const char *name;     /* memory type name */
  unsigned long *slot; /* slot in return struct */
} mem_table_struct;

static struct pwbuf {
	struct pwbuf *next;
	uid_t uid;
	char name[20];
} *pwhash[64];

static struct grpbuf {
    struct grpbuf *next;
    gid_t gid;
    char name[20];
} *grphash[64];

typedef struct status_table_struct {
    unsigned char name[7];        // /proc/*/status field name
    unsigned char len;            // name length
#ifdef LABEL_OFFSET
    long offset;                  // jump address offset
#else
    void *addr;
#endif
} status_table_struct;

typedef struct user_t{
	char name[21];
	char cpu[30];
	long long cput;
	char mem[30];
	long long memt;
	struct user_t *next;
}user_t, *user_p;

typedef struct process_t{
	char cmd[21];
	unsigned cput;//jiffies
	unsigned long memt;//kb
	unsigned long swap;//kb
	char rchar[10], wchar[10];
	struct process_t *next;
	unsigned long seconds;
	unsigned char alive;
}process_t, *process_p;

static int       Frames_libflags;       // PROC_FILLxxx flags (0 = need new)
static unsigned  Frame_maxtask;         // last known number of active tasks
                                        // ie. current 'size' of proc table
static unsigned  Frame_running,         // state categories for this frame
                 Frame_sleepin,
                 Frame_stopped,
                 Frame_zombied;
static float     Frame_tscale;          // so we can '*' vs. '/' WHEN 'pcpu'
static int       Frame_srtflg,          // the subject window's sort direction
                 Frame_ctimes,          // the subject window's ctimes flag
                 Frame_cmdlin;          // the subject window's cmdlin flag

/* obsolete */
unsigned long kb_main_shared;
/* old but still kicking -- the important stuff */
unsigned long kb_main_buffers;
unsigned long kb_main_cached;
unsigned long kb_main_free;
unsigned long kb_main_total;
unsigned long kb_swap_free;
unsigned long kb_swap_total;
/* recently introduced */
unsigned long kb_high_free;
unsigned long kb_high_total;
unsigned long kb_low_free;
unsigned long kb_low_total;
/* 2.4.xx era */
unsigned long kb_active;
unsigned long kb_inact_laundry;
unsigned long kb_inact_dirty;
unsigned long kb_inact_clean;
unsigned long kb_inact_target;
unsigned long kb_swap_cached;  /* late 2.4 and 2.6+ only */
/* derived values */
unsigned long kb_swap_used;
unsigned long kb_main_used;
/* 2.5.41+ */
unsigned long kb_writeback;
unsigned long kb_slab;
unsigned long nr_reversemaps;
unsigned long kb_committed_as;
unsigned long kb_dirty;
unsigned long kb_inactive;
unsigned long kb_mapped;
unsigned long kb_pagetables;
// seen on a 2.6.x kernel:
static unsigned long kb_vmalloc_chunk;
static unsigned long kb_vmalloc_total;
static unsigned long kb_vmalloc_used;
// seen on 2.6.24-rc6-git12
static unsigned long kb_anon_pages;
static unsigned long kb_bounce;
static unsigned long kb_commit_limit;
static unsigned long kb_nfs_unstable;
static unsigned long kb_swap_reclaimable;
static unsigned long kb_swap_unreclaimable;

static char str[100] = " ";

static int proc_table_size;

static int Cpu_tot;

static char buf[2048];

static int row_to_show = 7;

net_t NET;
	
int txt_fd;
int proc_fd; //结束进程记录文件的文件描述符
   
char _buf[2048];          // with help stuff, our buffer
char line_buf[2048];	//use to read one line from file

user_t user_head; //用户列表 记录用户的资源使用情况
user_p user_tail;

process_t process_head; //进程列表 记录存活进程 在生命周期内的资源使用情况
process_p process_tail;

static unsigned long long Hertz;
extern void __cyg_profile_func_enter(void*, void*);
extern void	__cyg_profile_func_exit(void *, void *);

static void ShowFormat(int interact, const char *glob);

static unsigned long long unhex(const char *__restrict cp);

static void status2proc(char *S, proc_t *__restrict P, int is_proc);

void TaskShow(proc_t *task);

user_p insert(user_p head, user_p node)	//赋值给tail
{
	if (head->next == NULL) {
		head->next = node;
		user_tail = node;
		node->next = NULL;
		return node;
	}
	user_tail->next = node;
	node->next = NULL;
	return node;
}

user_p check(user_p head, char name[21]) {
	while (head->next != NULL){
		if(strcmp(head->next->name, name) == 0){
				return head->next;
		}
		head = head->next;
	}
	return NULL;
}

user_p new_user(){
	user_p temp = (user_p)malloc(sizeof(user_t));
	temp->cput = 0;
	temp->memt = 0;
	return temp;
}

process_p insertProcess(process_p head, process_p node)	//赋值给tail
{
	if (head->next == NULL) {
		head->next = node;
		process_tail = node;
		node->next = NULL;
		return node;
	}
	process_tail->next = node;
	node->next = NULL;
	return node;
}

process_p checkProcess(process_p head, char name[21]) {
	while (head->next != NULL){
		if(strcmp(head->next->cmd, name) == 0){
				return head->next;
		}
		head = head->next;
	}
	return NULL;
}

process_p newProcess(){
	process_p temp = (process_p)malloc(sizeof(process_t));
	temp->cput = 0;
	temp->memt = 0;
	temp->swap = 0;
	temp->alive = 0;
	temp->seconds = 0;
	temp->next = NULL;
	return temp;
}

static void std_err (const char *str)
{
   static char buf[SMLBUFSIZ];

   fflush(stdout);
   /* we'll use our own buffer so callers can still use FormatMake() and, yes the
      leading tab is not the standard convention, but the standard is wrong
      -- OUR msg won't get lost in screen clutter, like so many others! */
   snprintf(buf, sizeof(buf), "\t%s: %s\n", "toptest", str);
   if (1) {
      fprintf(stderr, "%s\n", buf);
      exit(1);
   }
      /* not to worry, he'll change our exit code to 1 due to 'buf' */
   bye_bye(stderr, 1, buf);
}

static const char *FormatMake (const char *fmts, ...)
{
   va_list va;

   va_start(va, fmts);
   vsnprintf(_buf, sizeof(buf), fmts, va);
   va_end(va);
   return (const char *)_buf;
}

static int simple_nexttid(PROCTAB *__restrict const PT, const proc_t *__restrict const p, proc_t *__restrict const t, char *__restrict const path) {
	static struct direct *ent;		/* dirent handle */
	if(PT->taskdir_user != p->tgid){
		    if(PT->taskdir){
				closedir(PT->taskdir);
			}
	    	snprintf(path, 64, "/proc/%d/task", p->tgid);
		    PT->taskdir = opendir(path);
			if(!PT->taskdir) return 0;
			PT->taskdir_user = p->tgid;
	}
	for (;;) {
		ent = readdir(PT->taskdir);
		if((!ent) || (!ent->d_name)) return 0;
   	    if((*ent->d_name > '0') && (*ent->d_name <= '9')) break;
	}
	t->tid = strtoul(ent->d_name, NULL, 10);
	t->tgid = p->tgid;
	t->ppid = p->ppid;  // cover for kernel behavior? we want both actually...?
	snprintf(path, 64, "/proc/%d/task/%s", p->tgid, ent->d_name);
	return 1;
}

static int file2str(const char *directory, const char *what, char *ret, int cap){ //读取directory下what文件 存入ret
	static char filename[80];
	int fd, num_read;

	sprintf(filename, "%s/%s", directory, what);
	fd = open(filename, O_RDONLY, 0);
	if(fd == -1) return -1;
	num_read = read(fd, ret, cap - 1);
	close(fd);
	if(num_read <= 0) return -1;
	ret[num_read] = '\0';
	return num_read;
}

static void stat2proc(const char *S, proc_t *__restrict P){
	unsigned num;
	char *tmp;
	__cyg_profile_func_enter((void *)0x160, (void *)0x160);

	P->processor = 0;
	P->rtprio = -1;
	P->sched = -1;
	P->nlwp = 0;

	S = strchr(S, '(') + 1;
	tmp = strchr(S, ')');
	num = tmp - S;
	if(num >= sizeof P->cmd) num = sizeof P->cmd - 1;
	memcpy(P->cmd, S, num);
	P->cmd[num] = '\0';
	S = tmp + 2;                 // skip ") "

	num = sscanf(S,
	   "%c "
	   "%d %d %d %d %d "
	   "%lu %lu %lu %lu %lu "
	   "%Lu %Lu %Lu %Lu "  /* utime stime cutime cstime */
	   "%ld %ld "
	   "%d "
	   "%ld "
	   "%Lu "  /* start_time */
	   "%lu "
	   "%ld "
	   "%lu %"KLF"u %"KLF"u %"KLF"u %"KLF"u %"KLF"u "
	   "%*s %*s %*s %*s " /* discard, no RT signals & Linux 2.1 used hex */
	   "%"KLF"u %*lu %*lu "
	   "%d %d "
	   "%lu %lu",
	   &P->state,
	   &P->ppid, &P->pgrp, &P->session, &P->tty, &P->tpgid,
	   &P->flags, &P->min_flt, &P->cmin_flt, &P->maj_flt, &P->cmaj_flt,
	   &P->utime, &P->stime, &P->cutime, &P->cstime,
	   &P->priority, &P->nice,
	   &P->nlwp,
	   &P->alarm,
	   &P->start_time,
	   &P->vsize,
	   &P->rss,
	   &P->rss_rlim, &P->start_code, &P->end_code, &P->start_stack, &P->kstk_esp, &P->kstk_eip,
	   &P->wchan,
	   &P->exit_signal,
	   &P->processor,
	   &P->rtprio,
	   &P->sched
	);

	if(!P->nlwp){
		P->nlwp = 1;
	}

	__cyg_profile_func_exit((void *)0x160, (void *)0x160);
}

static void statm2proc(const char* s, proc_t *__restrict P) {
    int num;
    num = sscanf(s, "%ld %ld %ld %ld %ld %ld %ld",
	   &P->size, &P->resident, &P->share,
	   &P->trs, &P->lrs, &P->drs, &P->dt);
/*    fprintf(stderr, "statm2proc converted %d fields.\n",num); */
}


static void status2proc(char *S, proc_t *__restrict P, int is_proc){
    long Threads = 0;
    long Tgid = 0;
    long Pid = 0;

  static const unsigned char asso[] =
    {
      61, 61, 61, 61, 61, 61, 61, 61, 61, 61,
      61, 61, 61, 61, 61, 61, 61, 61, 61, 61,
      61, 61, 61, 61, 61, 61, 61, 61, 61, 61,
      61, 61, 61, 61, 61, 61, 61, 61, 61, 61,
      61, 61, 61, 61, 61, 61, 61, 61, 61, 61,
      61, 61, 61, 61, 61, 61, 61, 61, 15, 61,
      61, 61, 61, 61, 61, 61, 30,  3,  5,  5,
      61,  5, 61,  8, 61, 61,  3, 61, 10, 61,
       6, 61, 13,  0, 30, 25,  0, 61, 61, 61,
      61, 61, 61, 61, 61, 61, 61,  3, 61, 13,
       0,  0, 61, 30, 61, 25, 61, 61, 61,  0,
      61, 61, 61, 61,  5, 61,  0, 61, 61, 61,
       0, 61, 61, 61, 61, 61, 61, 61
    };

    static const status_table_struct table[] = {
      F(VmStk)
      NUL NUL
      F(State)
      NUL
      F(VmExe)
      F(ShdPnd)
      NUL
      F(VmData)
      NUL
      F(Name)
      NUL NUL
      F(VmRSS)
      NUL NUL
      F(VmLck)
      NUL NUL NUL
      F(Gid)
      F(Pid)
      NUL NUL NUL
      F(VmSize)
      NUL NUL
      F(VmLib)
      NUL NUL
      F(PPid)
      NUL
      F(SigCgt)
      NUL
      F(Threads)
      F(SigPnd)
      NUL
      F(SigIgn)
      NUL
      F(Uid)
      NUL NUL NUL NUL NUL NUL NUL NUL NUL
      NUL NUL NUL NUL NUL
      F(Tgid)
      NUL NUL NUL NUL
      F(SigBlk)
      NUL NUL NUL
    };

#undef F
#undef NUL

ENTER(0x220);

    P->vm_size = 0;
    P->vm_lock = 0;
    P->vm_rss  = 0;
    P->vm_data = 0;
    P->vm_stack= 0;
    P->vm_exe  = 0;
    P->vm_lib  = 0;
    P->nlwp    = 0;
    P->signal[0] = '\0';  // so we can detect it as missing for very old kernels

    goto base;

    for(;;){
        char *colon;
        status_table_struct entry;

        // advance to next line
        S = strchr(S, '\n');
        if(!S) break;  // if no newline
        S++;

        // examine a field name (hash and compare)
    base:
        if(!*S) break;
        entry = table[63 & (asso[S[3]] + asso[S[2]] + asso[S[0]])];
        colon = strchr(S, ':');
        if(!colon) break;
        if(colon[1]!='\t') break;
        if(colon-S != entry.len) continue;
        if(memcmp(entry.name,S,colon-S)) continue;

        S = colon+2; // past the '\t'

        goto *entry.addr;

    case_Name:{
        unsigned u = 0;
        while(u < sizeof P->cmd - 1u){
            int c = *S++;
            if(c=='\n') break;
            if(c=='\0') break; // should never happen
            if(c=='\\'){
                c = *S++;
                if(c=='\n') break; // should never happen
                if(!c)      break; // should never happen
                if(c=='n') c='\n'; // else we assume it is '\\'
            }
            P->cmd[u++] = c;
        }
        P->cmd[u] = '\0';
        S--;   // put back the '\n' or '\0'
        continue;
    }
#ifdef SIGNAL_STRING
		case_ShdPnd:
			memcpy(P->signal, S, 16);
			P->signal[16] = '\0';
			continue;
		case_SigBlk:
			memcpy(P->blocked, S, 16);
			P->blocked[16] = '\0';
			continue;
		case_SigCgt:
			memcpy(P->sigcatch, S, 16);
			P->sigcatch[16] = '\0';
			continue;
		case_SigIgn:
			memcpy(P->sigignore, S, 16);
			P->sigignore[16] = '\0';
			continue;
		case_SigPnd:
			memcpy(P->_sigpnd, S, 16);
			P->_sigpnd[16] = '\0';
			continue;
#else
		case_ShdPnd:
			P->signal = unhex(S);
			continue;
		case_SigBlk:
			P->blocked = unhex(S);
			continue;
		case_SigCgt:
			P->sigcatch = unhex(S);
			continue;
		case_SigIgn:
			P->sigignore = unhex(S);
			continue;
		case_SigPnd:
			P->_sigpnd = unhex(S);
			continue;
#endif
		case_State:
			P->state = *S;
			continue;
		case_Tgid:
			Tgid = strtol(S,&S,10);
			continue;
		case_Pid:
			Pid = strtol(S,&S,10);
			continue;
		case_PPid:
			P->ppid = strtol(S,&S,10);
			continue;
		case_Threads:
			Threads = strtol(S,&S,10);
			continue;
		case_Uid:
			P->ruid = strtol(S,&S,10);
			P->euid = strtol(S,&S,10);
			P->suid = strtol(S,&S,10);
			P->fuid = strtol(S,&S,10);
			continue;
		case_Gid:
			P->rgid = strtol(S,&S,10);
			P->egid = strtol(S,&S,10);
			P->sgid = strtol(S,&S,10);
			P->fgid = strtol(S,&S,10);
			continue;
		case_VmData:
			P->vm_data = strtol(S,&S,10);
			continue;
		case_VmExe:
			P->vm_exe = strtol(S,&S,10);
			continue;
		case_VmLck:
			P->vm_lock = strtol(S,&S,10);
			continue;
		case_VmLib:
			P->vm_lib = strtol(S,&S,10);
			continue;
		case_VmRSS:
			P->vm_rss = strtol(S,&S,10);
			continue;
		case_VmSize:
			P->vm_size = strtol(S,&S,10);
			continue;
		case_VmStk:
			P->vm_stack = strtol(S,&S,10);
			continue;
		}


    // recent kernels supply per-tgid pending signals
    if(!is_proc || !P->signal[0]){
	memcpy(P->signal, P->_sigpnd, 16);
	P->signal[16] = '\0';
    }

    // Linux 2.4.13-pre1 to max 2.4.xx have a useless "Tgid"
    // that is not initialized for built-in kernel tasks.
    // Only 2.6.0 and above have "Threads" (nlwp) info.

    if(Threads){
       P->nlwp = Threads;
       P->tgid = Tgid;     // the POSIX PID value
       P->tid  = Pid;      // the thread ID
    }else{
       P->nlwp = 1;
       P->tgid = Pid;
       P->tid  = Pid;
    }

LEAVE(0x220);
}

void io2proc(char *S, proc_t *__restrict P)
{
	char name[21];
	long long temp;
	sscanf(S,"rchar: %lld\n", &temp);
	while(*S++ != '\n');
	if(temp > 1073741824){
		sprintf(P->rchar, "%dGB", temp / 1024 / 1024 / 1024);
	}
	else if(temp > 1048576){
		sprintf(P->rchar, "%dMB", temp / 1024 / 1024);
	}
	else if(temp > 104){
		sprintf(P->rchar, "%dKB", temp / 1024);
	}
	else{
		sprintf(P->rchar, "%dB", temp);
	}
	sscanf(S,"wchar: %lld\n", &temp);
	while(*S++ != '\n');
	if(temp > 1073741824){
		sprintf(P->rchar, "%dGB", temp / 1024 / 1024 / 1024);
	}
	else if(temp > 1048576){
		sprintf(P->wchar, "%dMB", temp / 1024 / 1024);
	}
	else if(temp > 104){
		sprintf(P->wchar, "%dKB", temp / 1024);
	}
	else{
		sprintf(P->wchar, "%dB", temp);
	}
	sscanf(S,"%s%d\n", name, &temp);
	while(*S++ != '\n');
	sscanf(S,"%s%d\n", name, &temp);
	while(*S++ != '\n');
	sscanf(S,"%s%d\n", name, &temp);
	while(*S++ != '\n');
	sscanf(S,"%s%d\n", name, &temp);
	while(*S++ != '\n');
	sscanf(S,"%s%d\n", name, &temp);
}

static char** file2strvec(const char* directory, const char* what) {
    char buf[2048];	/* read buf bytes at a time */
    char *p, *rbuf = 0, *endbuf, **q, **ret;
    int fd, tot = 0, n, c, end_of_file = 0;
    int align;

    sprintf(buf, "%s/%s", directory, what);
    fd = open(buf, O_RDONLY, 0);
    if(fd==-1) return NULL;

    /* read whole file into a memory buffer, allocating as we go */
    while ((n = read(fd, buf, sizeof buf - 1)) > 0) {
	if (n < (int)(sizeof buf - 1))
	    end_of_file = 1;
	if (n == 0 && rbuf == 0)
	    return NULL;	/* process died between our open and read */
	if (n < 0) {
	    if (rbuf)
		free(rbuf);
	    return NULL;	/* read error */
	}
	if (end_of_file && buf[n-1])		/* last read char not null */
	    buf[n++] = '\0';			/* so append null-terminator */
	rbuf = realloc(rbuf, tot + n);		/* allocate more memory */
	memcpy(rbuf + tot, buf, n);		/* copy buffer into it */
	tot += n;				/* increment total byte ctr */
	if (end_of_file)
	    break;
    }
    close(fd);
    if (n <= 0 && !end_of_file) {
	if (rbuf) free(rbuf);
	return NULL;		/* read error */
    }
    endbuf = rbuf + tot;			/* count space for pointers */
    align = (sizeof(char*)-1) - ((tot + sizeof(char*)-1) & (sizeof(char*)-1));
    for (c = 0, p = rbuf; p < endbuf; p++)
    	if (!*p)
	    c += sizeof(char*);
    c += sizeof(char*);				/* one extra for NULL term */

    rbuf = realloc(rbuf, tot + c + align);	/* make room for ptrs AT END */
    endbuf = rbuf + tot;			/* addr just past data buf */
    q = ret = (char**) (endbuf+align);		/* ==> free(*ret) to dealloc */
    *q++ = p = rbuf;				/* point ptrs to the strings */
    endbuf--;					/* do not traverse final NUL */
    while (++p < endbuf) 
    	if (!*p)				/* NUL char implies that */
	    *q++ = p+1;				/* next string -> next char */

    *q = 0;					/* null ptr list terminator */
    return ret;
}

char *user_from_uid(uid_t uid) {
    struct pwbuf **p;
	struct passwd *pw;

	p = &pwhash[(uid) & 63];
	while (*p) {
		if ((*p)->uid == uid)
			return((*p)->name);
		p = &(*p)->next;
	}
	*p = (struct pwbuf *) malloc(sizeof(struct pwbuf));
	(*p)->uid = uid;
	pw = getpwuid(uid);
	if(!pw || strlen(pw->pw_name) >= 20)
		sprintf((*p)->name, "%u", uid);
	else
	    strcpy((*p)->name, pw->pw_name);

	(*p)->next = NULL;
	return((*p)->name);
}

char *group_from_gid(gid_t gid) {
    struct grpbuf **g;
	struct group *gr;

	g = &grphash[(gid) & 63];
	while (*g) {
		if ((*g)->gid == gid)
			return((*g)->name);
		g = &(*g)->next;
	}
    *g = (struct grpbuf *) malloc(sizeof(struct grpbuf));
	(*g)->gid = gid;
	gr = getgrgid(gid);
	if (!gr || strlen(gr->gr_name) >= 20)
	    sprintf((*g)->name, "%u", gid);
	else
	        strcpy((*g)->name, gr->gr_name);
	(*g)->next = NULL;
	return((*g)->name);
}

static proc_t* simple_readtask(PROCTAB *__restrict const PT, const proc_t *__restrict const P, proc_t *__restrict const t, char *__restrict const path) {
	    static struct stat sb;		// stat() buffer
		static char sbuf[1024];	// buffer for stat,statm
		unsigned flags = PT->flags;

		if(stat(path, &sb) == -1){
			goto next_task;
		}

		t->euid = sb.st_uid;
		t->egid = sb.st_gid;

		if(flags & 0x0040){
			if(file2str(path, "stat", sbuf, sizeof(sbuf)) == -1){
				goto next_task;
			}
			stat2proc(sbuf, t);
		}

		if(flags & 0x0001){
			t->size = P->size;
			t->resident = P->resident;
			t->share = P->share;
			t->trs = P->trs;
			t->lrs = P->lrs;
			t->drs = P->drs;
			t->dt = P->dt;
		}

		if(flags & 0x0020){
			if(file2str(path, "status", sbuf, sizeof(sbuf)) != -1){
					status2proc(sbuf, t, 0);
			}
		}

		if(flags & 0x0008){
			memcpy(t->euser, user_from_uid(t->euid), sizeof(t->euser));
			if(flags & 0x0020){
				memcpy(t->rgroup, user_from_uid(t->euid), sizeof(t->euser));
				memcpy(t->sgroup, user_from_uid(t->suid), sizeof(t->suser));
				memcpy(t->fgroup, user_from_uid(t->fuid), sizeof(t->fuser));
			}
		}

		if(flags & 0x0010){
			memcpy(t->euser, user_from_uid(t->euid), sizeof(t->euser));
			if(flags & 0x0020){
				memcpy(t->rgroup, user_from_uid(t->euid), sizeof(t->euser));
				memcpy(t->sgroup, user_from_uid(t->suid), sizeof(t->suser));
				memcpy(t->fgroup, user_from_uid(t->fuid), sizeof(t->fuser));
			}
		}

		t->cmdline = P->cmdline;
		t->environ = P->environ;
		t->ppid = P->ppid;
		return t;
next_task:
		return NULL;
}

static unsigned long long unhex(const char *__restrict cp){
    unsigned long long ull = 0;
    for(;;){
        char c = *cp++;
        if(c<0x30) break;
        ull = (ull<<4) | (c - (c>0x57) ? 0x57 : 0x30) ;
    }
    return ull;
}

static proc_t* simple_readproc(PROCTAB *__restrict const PT, proc_t *__restrict const p) {
	static struct stat sb;		// stat() buffer
	static char sbuf[1024];	// buffer for stat,statm
	char *__restrict const path = PT->path;
	unsigned flags = PT->flags;

	if (stat(path, &sb) == -1)	//获取文件信息存入sb
			goto next_proc;

	if ((flags & PROC_UID) && !XinLN(uid_t, sb.st_uid, PT->uids, PT->nuid))
			goto next_proc;			/* not one of the requested uids */

	p->euid = sb.st_uid;			/* need a way to get real uid */
	p->egid = sb.st_gid;			/* need a way to get real gid */

	if (flags & PROC_FILLSTAT) {         /* read, parse /proc/#/stat */
		if (file2str(path, "stat", sbuf, sizeof sbuf) == -1 )
				    goto next_proc;			/* error reading /proc/#/stat */
		stat2proc(sbuf, p);				/* parse /proc/#/stat */
	}

    if (flags & PROC_FILLMEM) {	/* read, parse /proc/#/statm */
		if (file2str(path, "statm", sbuf, sizeof sbuf) != -1 )
		    statm2proc(sbuf, p);		/* ignore statm errors here */
	    }						/* statm fields just zero */

	if (flags & PROC_FILLSTATUS) {         /* read, parse /proc/#/status */
		if (file2str(path, "status", sbuf, sizeof sbuf) != -1 ){
		    status2proc(sbuf, p, 1);
	    }
	}
	
	if(flags & PROC_FILLIO) {
		if (file2str(path, "io", sbuf,sizeof sbuf) != -1){
			io2proc(sbuf, p);
		}
	}
	// if multithreaded, some values are crap
    if(p->nlwp > 1){
      p->wchan = (long long)~0ull;
    }

    /* some number->text resolving which is time consuming and kind of insane */
    if (flags & PROC_FILLUSR){
		memcpy(p->euser,   user_from_uid(p->euid), sizeof p->euser);
        if(flags & PROC_FILLSTATUS) {
            memcpy(p->ruser,   user_from_uid(p->ruid), sizeof p->ruser);
            memcpy(p->suser,   user_from_uid(p->suid), sizeof p->suser);
            memcpy(p->fuser,   user_from_uid(p->fuid), sizeof p->fuser);
        }
    }

    /* some number->text resolving which is time consuming and kind of insane */
    if (flags & PROC_FILLGRP){
        memcpy(p->egroup, group_from_gid(p->egid), sizeof p->egroup);
        if(flags & PROC_FILLSTATUS) {
            memcpy(p->rgroup, group_from_gid(p->rgid), sizeof p->rgroup);
            memcpy(p->sgroup, group_from_gid(p->sgid), sizeof p->sgroup);
            memcpy(p->fgroup, group_from_gid(p->fgid), sizeof p->fgroup);
        }
    }

    if ((flags & PROC_FILLCOM) || (flags & PROC_FILLARG))	/* read+parse /proc/#/cmdline */
		p->cmdline = file2strvec(path, "cmdline");
    else
        p->cmdline = NULL;

    if (flags & PROC_FILLENV)			/* read+parse /proc/#/environ */
		p->environ = file2strvec(path, "environ");
    else
        p->environ = NULL;
    
    return p;
next_proc:
    return NULL;
}

static int listed_nextpid(PROCTAB *__restrict const PT, proc_t *__restrict const p) {
  char *__restrict const path = PT->path;
  pid_t tgid = *(PT->pids)++;
  if( tgid ){
    snprintf(path, 64, "/proc/%d", tgid);
    p->tgid = tgid;
    p->tid = tgid;  // they match for leaders
  }
  return tgid;
}

static int simple_nextpid(PROCTAB *__restrict const PT, proc_t *__restrict const p) { //遍历/proc中的pid目录
  static struct direct *ent;		/* dirent handle */
  char *__restrict const path = PT->path;
  for (;;) {
    ent = readdir(PT->procfs);
    if(!ent || !ent->d_name) return 0;
    if(*ent->d_name > '0' && *ent->d_name <= '9' ) break;
  }
  p->tgid = strtoul(ent->d_name, NULL, 10);
  p->tid = p->tgid;
  memcpy(path, "/proc/", 6);
  strcpy(path+6, ent->d_name);  // trust /proc to not contain evil top-level entries
  return 1;
}


PROCTAB *openproc(int flags){
	PROCTAB *PT = (PROCTAB *)malloc(sizeof(PROCTAB));

	PT->taskdir = NULL;
	PT->taskdir_user = -1;
	PT->taskfinder = simple_nexttid;
	PT->taskreader = simple_readtask;

	PT->reader = simple_readproc;
	if (flags & PROC_PID){
      PT->procfs = NULL;
      PT->finder = listed_nextpid; //pid递增遍历
    }else{
      PT->procfs = opendir("/proc");
      if(!PT->procfs) return NULL;
      PT->finder = simple_nextpid; //用readdir遍历目录
    }
    PT->flags = flags;

    return PT;
}

proc_t* readproc(PROCTAB *__restrict const PT, proc_t *__restrict p) {
  proc_t *ret;
  proc_t *saved_p;

  PT->did_fake=0;


  saved_p = p;
  if(!p) p = (proc_t *)malloc(sizeof(*p)); /* passed buf or alloced mem */

  while(1){
    // fills in the path, plus p->tid and p->tgid
    if (! PT->finder(PT,p) ) goto out;

    // go read the process data
    ret = PT->reader(PT,p);
    if(ret) return ret;
  }

out:
  if(!saved_p) free(p);
  // FIXME: maybe set tid to -1 here, for "-" in display?
  return NULL;
}

static int sort_HST_t (const HST_t *P, const HST_t *Q)
{
   return P->pid - Q->pid;
}

static void GetProInfo (proc_t *this)
{
   static HST_t    *hist_sav = NULL;
   static HST_t    *hist_new = NULL;
   static unsigned  hist_siz = 0;       // number of structs
   static unsigned  maxt_sav;           // prior frame's max tasks
   TIC_t tics;

   #if DEBUG
   printf("prochlp:%c\n", this->state);
   #endif
   switch (this->state) {
      case 'R':
         Frame_running++;
         break;
      case 'S':
      case 'D':
         Frame_sleepin++;
         break;
      case 'T':
         Frame_stopped++;
         break;
      case 'Z':
         Frame_zombied++;
         break;
   }

   if (Frame_maxtask+1 >= hist_siz) {
      hist_siz = hist_siz * 5 / 4 + 100;  // grow by at least 25%
      hist_sav = (HST_t *)realloc(hist_sav, sizeof(HST_t) * hist_siz);
      hist_new = (HST_t *)realloc(hist_new, sizeof(HST_t) * hist_siz);
   }
   /* calculate time in this process; the sum of user time (utime) and
      system time (stime) -- but PLEASE dont waste time and effort on
      calcs and saves that go unused, like the old top! */
   hist_new[Frame_maxtask].pid  = this->tid;
   hist_new[Frame_maxtask].tics = tics = (this->utime + this->stime);

   HST_t tmp;
   const HST_t *ptr;
   tmp.pid = this->tid;
   ptr = bsearch(&tmp, hist_sav, maxt_sav, sizeof tmp, sort_HST_t);
   if(ptr) {
   	tics -= ptr->tics;
	MessageShow(FormatMake("ptr not null tics=%d", tics));
   }

   this->pcpu = tics;

   Frame_maxtask++;
}

static void summaryhlp (CPU_t *cpu, const char *pfx)
{
#define TRIMz(x)  ((tz = (SIC_t)(x)) < 0 ? 0 : tz)
   SIC_t u_frme, s_frme, n_frme, i_frme, w_frme, x_frme, y_frme, z_frme, tot_frme, tz;
   float scale;

   u_frme = cpu->u - cpu->u_sav;
   s_frme = cpu->s - cpu->s_sav;
   n_frme = cpu->n - cpu->n_sav;
   i_frme = TRIMz(cpu->i - cpu->i_sav);
   w_frme = cpu->w - cpu->w_sav;
   x_frme = cpu->x - cpu->x_sav;
   y_frme = cpu->y - cpu->y_sav;
   z_frme = cpu->z - cpu->z_sav;
   tot_frme = u_frme + s_frme + n_frme + i_frme + w_frme + x_frme + y_frme + z_frme;
   if (tot_frme < 1) tot_frme = 1;
   scale = 100.0 / (float)tot_frme;

   // display some kinda' cpu state percentages
   // (who or what is explained by the passed prefix)
   ShowFormat(
      0,
      FormatMake(
         STATES_line2x4,
         pfx,
         (float)u_frme * scale,
         (float)s_frme * scale,
         (float)n_frme * scale,
         (float)i_frme * scale,
         (float)w_frme * scale,
         (float)x_frme * scale,
         (float)y_frme * scale,
         (float)z_frme * scale
      )
   );
	char *_p = _buf;
	write(txt_fd, _p, strlen(_p));
#ifdef TEST
   getchar();
#endif
   // remember for next time around
   cpu->u_sav = cpu->u;
   cpu->s_sav = cpu->s;
   cpu->n_sav = cpu->n;
   cpu->i_sav = cpu->i;
   cpu->w_sav = cpu->w;
   cpu->x_sav = cpu->x;
   cpu->y_sav = cpu->y;
   cpu->z_sav = cpu->z;

#undef TRIMz
}

static proc_t **ProcsRefresh (proc_t **table, int flags){
	PROCTAB *PT = PT = openproc(flags); //赋与各个读取函数
	proc_t *ptsk;
	int idx = 0;
	static int Switch = 0;
	Switch++;
	row_to_show = 7;
	TaskTitleShow();
	row_to_show = 8;
	putp(tgoto(cursor_address, 0, row_to_show));
	
	if(table == NULL){
		proc_table_size = 10;
		#if DEBUG
		printf("procs_refresh\n");
		#endif
		table = (proc_t **)malloc(sizeof(proc_t *) * 10); //第一次运行时分配空间
	}

	Frame_maxtask = Frame_running = Frame_sleepin = Frame_stopped = Frame_zombied = 0;
	
	while(1){
		if((ptsk = readproc(PT, NULL)) != NULL){
			GetProInfo(ptsk); //获取进程信息
			user_p user = check(&user_head, ptsk->euser);
			process_p process = checkProcess(&process_head, ptsk->cmd);
			if(user == NULL){
				user = new_user();
				strcpy(user->name, ptsk->euser);
				user->cput = ptsk->pcpu;
				user->memt = ptsk->size;
				sprintf(user->cpu, "%llds", user->cput / 100);
				sprintf(user->mem, "%lldB", user->memt);
				user_tail = insert(&user_head,  user);
			}
			else{
				user->cput += ptsk->pcpu;
				user->memt += ptsk->size;
				sprintf(user->cpu, "%llds", user->cput / 100);
				sprintf(user->mem, "%lldB", user->memt);
			}
			if(process == NULL){
				process = newProcess();
				strcpy(process->cmd, ptsk->cmd);
				process->cput = ptsk->pcpu;
				process->memt = ptsk->vm_rss;
				process->swap = ptsk->vm_size - ptsk->vm_rss;
				strcpy(process->rchar, ptsk->rchar);
				strcpy(process->wchar, ptsk->wchar);
				process_tail = insertProcess(&process_head, process);
			}
			else{
				process->cput = ptsk->pcpu;
				process->memt += ptsk->vm_rss;
				process->swap += ptsk->vm_size - ptsk->vm_rss;
				strcpy(process->rchar, ptsk->rchar);
				strcpy(process->wchar, ptsk->wchar);
			}
			process->alive = 1;
			process->seconds++;
			if((Switch / 3 ) % 2 == 1){ //减少显示的数目
				TaskShow(ptsk);
				row_to_show++;
			}
			else if(ptsk->tid > 3000){
				TaskShow(ptsk);
				row_to_show++;
			}
			table[idx++] = ptsk;
			if(idx == proc_table_size){ //和c++向量一样的考量
				proc_table_size = proc_table_size * 2;
				table = (proc_t **)realloc(table, sizeof(proc_t *) * proc_table_size);
			}
		}
		else{
			break;
		}
	}
	#if DEBUG
	printf("procs_refresh\n");
	#endif
	putp(tgoto(cursor_address, 0, 3));
	return table;
		
}

static CPU_t *CpusRead (CPU_t *cpus)
{
   static FILE *fp = NULL;
   int i;
   int num;
   // enough for a /proc/stat CPU line (not the intr line)
   char buf[2048];

   /* by opening this file once, we'll avoid the hit on minor page faults
      (sorry Linux, but you'll have to close it for us) */
   if (!fp) {
      if (!(fp = fopen("/proc/stat", "r")))
         std_err(FormatMake("Failed /proc/stat open: %s", strerror(errno)));
      /* note: we allocate one more CPU_t than Cpu_tot so that the last slot
               can hold tics representing the /proc/stat cpu summary (the first
               line read) -- that slot supports our View_CPUSUM toggle */
      cpus = (CPU_t *)realloc(cpus, (1 + Cpu_tot) * sizeof(CPU_t));
   }
   rewind(fp);
   fflush(fp);

   // first value the last slot with the cpu summary line
   if (!fgets(buf, sizeof(buf), fp)) std_err("failed /proc/stat read");
   cpus[Cpu_tot].x = 0;  // FIXME: can't tell by kernel version number
   cpus[Cpu_tot].y = 0;  // FIXME: can't tell by kernel version number
   cpus[Cpu_tot].z = 0;  // FIXME: can't tell by kernel version number
   num = sscanf(buf, "cpu %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu",
      &cpus[Cpu_tot].u,
      &cpus[Cpu_tot].n,
      &cpus[Cpu_tot].s,
      &cpus[Cpu_tot].i,
      &cpus[Cpu_tot].w,
      &cpus[Cpu_tot].x,
      &cpus[Cpu_tot].y,
      &cpus[Cpu_tot].z
   );
   if (num < 4)
         std_err("failed /proc/stat read");

   // and just in case we're 2.2.xx compiled without SMP support...
   if (Cpu_tot == 1) {
      cpus[1].id = 0;
      memcpy(cpus, &cpus[1], sizeof(CPU_t));
   }

   // now value each separate cpu's tics
   for (i = 0; 1 < Cpu_tot && i < Cpu_tot; i++) {
      if (!fgets(buf, sizeof(buf), fp)) std_err("failed /proc/stat read");
      cpus[i].x = 0;  // FIXME: can't tell by kernel version number
      cpus[i].y = 0;  // FIXME: can't tell by kernel version number
      cpus[i].z = 0;  // FIXME: can't tell by kernel version number
      num = sscanf(buf, "cpu%u %Lu %Lu %Lu %Lu %Lu %Lu %Lu %Lu",
         &cpus[i].id,
         &cpus[i].u, &cpus[i].n, &cpus[i].s, &cpus[i].i, &cpus[i].w, &cpus[i].x, &cpus[i].y, &cpus[i].z
      );
      if (num < 4)
            std_err("failed /proc/stat read");
   }
   return cpus;
}

static int compare_mem_table_structs(const void *a, const void *b){
  return strcmp(((const mem_table_struct*)a)->name,((const mem_table_struct*)b)->name);
}

void MemRead(void){
  char namebuf[16]; /* big enough to hold any row name */
  mem_table_struct findme = { namebuf, NULL};
  mem_table_struct *found;
  char *head;
  char *tail;
  static const mem_table_struct mem_table[] = {
  {"Active",       &kb_active},       // important
  {"AnonPages",    &kb_anon_pages},
  {"Bounce",       &kb_bounce},
  {"Buffers",      &kb_main_buffers}, // important
  {"Cached",       &kb_main_cached},  // important
  {"CommitLimit",  &kb_commit_limit},
  {"Committed_AS", &kb_committed_as},
  {"Dirty",        &kb_dirty},        // kB version of vmstat nr_dirty
  {"HighFree",     &kb_high_free},
  {"HighTotal",    &kb_high_total},
  {"Inact_clean",  &kb_inact_clean},
  {"Inact_dirty",  &kb_inact_dirty},
  {"Inact_laundry",&kb_inact_laundry},
  {"Inact_target", &kb_inact_target},
  {"Inactive",     &kb_inactive},     // important
  {"LowFree",      &kb_low_free},
  {"LowTotal",     &kb_low_total},
  {"Mapped",       &kb_mapped},       // kB version of vmstat nr_mapped
  {"MemFree",      &kb_main_free},    // important
  {"MemShared",    &kb_main_shared},  // important, but now gone!
  {"MemTotal",     &kb_main_total},   // important
  {"NFS_Unstable", &kb_nfs_unstable},
  {"PageTables",   &kb_pagetables},   // kB version of vmstat nr_page_table_pages
  {"ReverseMaps",  &nr_reversemaps},  // same as vmstat nr_page_table_pages
  {"SReclaimable", &kb_swap_reclaimable}, // "swap reclaimable" (dentry and inode structures)
  {"SUnreclaim",   &kb_swap_unreclaimable},
  {"Slab",         &kb_slab},         // kB version of vmstat nr_slab
  {"SwapCached",   &kb_swap_cached},
  {"SwapFree",     &kb_swap_free},    // important
  {"SwapTotal",    &kb_swap_total},   // important
  {"VmallocChunk", &kb_vmalloc_chunk},
  {"VmallocTotal", &kb_vmalloc_total},
  {"VmallocUsed",  &kb_vmalloc_used},
  {"Writeback",    &kb_writeback},    // kB version of vmstat nr_writeback
  };
  const int mem_table_count = sizeof(mem_table)/sizeof(mem_table_struct);

  FILE_TO_BUF(MEMINFO_FILE, meminfo_fd);

  kb_inactive = ~0UL;

  head = buf;
  for(;;){
    tail = strchr(head, ':');
    if(!tail) break;
    *tail = '\0';
    if(strlen(head) >= sizeof(namebuf)){
      head = tail+1;
      goto nextline;
    }
    strcpy(namebuf,head);
    found = bsearch(&findme, mem_table, mem_table_count,
        sizeof(mem_table_struct), compare_mem_table_structs
    );
    head = tail+1;
    if(!found) goto nextline;
    *(found->slot) = strtoul(head,&tail,10);
nextline:
    tail = strchr(head, '\n');
    if(!tail) break;
    head = tail+1;
  }
  if(!kb_low_total){  /* low==main except with large-memory support */
    kb_low_total = kb_main_total;
    kb_low_free  = kb_main_free;
  }
  if(kb_inactive==~0UL){
    kb_inactive = kb_inact_dirty + kb_inact_clean + kb_inact_laundry;
  }
  kb_swap_used = kb_swap_total - kb_swap_free;
  kb_main_used = kb_main_total - kb_main_free;
}


static void ShowFormat(int interact, const char *glob){
	char *line_end, line[2048];
	long long cols;
	while((line_end = strchr(glob, '\n')) != NULL){
		cols = line_end - glob;
		memcpy(line, glob, cols);
		line[cols] = '\0';
		PUTT("%s%s\n", line, clr_eol);
		glob = line_end + 1; //下一行
	}
	if (*glob) PUTT("%s", glob); //如果有最后一行
}

void NetRead(void) //获取网络信息
{
	char buf[2048];
	char *p = buf;
	static long long GB = 1024 * 1024 * 1024;
	static long long MB = 1024 * 1024;
	static long long KB = 1024;
	file2str("/proc/1/net", "dev", buf, sizeof buf);
	while(*(p++) != ':');
	sscanf(p, "%lld%*lld%*lld%*lld%*lld%*lld%*lld%*lld%lld", &NET.lo_bytes_receive, &NET.lo_bytes_transmit);
	if(NET.lo_bytes_receive > GB){
		sprintf(NET.lo_bytes_receive_s, "%lldGB", NET.lo_bytes_receive / GB);
	}
	else if(NET.lo_bytes_receive > MB){
		sprintf(NET.lo_bytes_receive_s, "%lldMB", NET.lo_bytes_receive / MB);
	}
	else if(NET.lo_bytes_receive > KB){
		sprintf(NET.lo_bytes_receive_s, "%lldKB", NET.lo_bytes_receive / KB);
	}
	else{
		sprintf(NET.lo_bytes_receive_s, "%lldB", NET.lo_bytes_receive);
	}
	if(NET.lo_bytes_transmit > GB){
		sprintf(NET.lo_bytes_transmit_s, "%lldGB", NET.lo_bytes_transmit / GB);
	}
	else if(NET.lo_bytes_transmit > MB){
		sprintf(NET.lo_bytes_transmit_s, "%lldMB", NET.lo_bytes_transmit / MB);
	}
	else if(NET.lo_bytes_transmit > KB){
		sprintf(NET.lo_bytes_transmit_s, "%lldkB", NET.lo_bytes_transmit / KB);
	}
	else{
		sprintf(NET.lo_bytes_transmit_s, "%lldB", NET.lo_bytes_transmit);
	}
	while(*p++ != ':');
	sscanf(p, "%lld%*lld%*lld%*lld%*lld%*lld%*lld%*lld%lld", &NET.eth0_bytes_receive, &NET.eth0_bytes_transmit);
	if(NET.eth0_bytes_receive > GB){
		sprintf(NET.eth0_bytes_receive_s, "%lldGB", NET.eth0_bytes_receive / GB);
	}
	else if(NET.eth0_bytes_receive > MB){
		sprintf(NET.eth0_bytes_receive_s, "%lldMB", NET.eth0_bytes_receive / MB);
	}
	else if(NET.eth0_bytes_receive > KB){
		sprintf(NET.eth0_bytes_receive_s, "%lldKB", NET.eth0_bytes_receive / KB);
	}
	else{
		sprintf(NET.eth0_bytes_receive_s, "%lldB", NET.eth0_bytes_receive);
	}
	if(NET.eth0_bytes_transmit > GB){
		sprintf(NET.eth0_bytes_transmit_s, "%lldGB", NET.eth0_bytes_transmit / GB);
	}
	else if(NET.eth0_bytes_transmit > MB){
		sprintf(NET.eth0_bytes_transmit_s, "%lldMB", NET.eth0_bytes_transmit / MB);
	}
	else if(NET.eth0_bytes_transmit > KB){
		sprintf(NET.eth0_bytes_transmit_s, "%lldKB", NET.eth0_bytes_transmit / KB);
	}
	else{
		sprintf(NET.eth0_bytes_transmit_s, "%lldB", NET.eth0_bytes_transmit);
	}
}

void NetTitleShow(void)
{
	putp(tgoto(cursor_address, 0, 0));
	putp(clr_eol);
	printf(NET_TITLE);
	write(txt_fd, "\n", 1);
	write(txt_fd, NET_TITLE, strlen(NET_TITLE));
	write(txt_fd, "\n", 1);
#ifdef TEST
   getchar();
#endif
	putp(tgoto(cursor_address, 0, row_to_show));
}

void NetShow()
{
	char temp[200];
	putp(tgoto(cursor_address, 0, 1));
	putp(clr_eol);
	sprintf(temp, NET_line, NET.lo_bytes_receive_s, NET.lo_bytes_transmit_s, NET.eth0_bytes_receive_s, NET.eth0_bytes_transmit_s);
	printf(temp);
	write(txt_fd, temp, strlen(temp));
#ifdef TEST
   getchar();
#endif
	putp(tgoto(cursor_address, 0, row_to_show));
}

static proc_t **summary_show (void){
	static proc_t **p_table = NULL;
	static CPU_t *smpcpu = NULL;

	p_table = ProcsRefresh(p_table, PROC_FILLIO | PROC_FILLSTATUS | PROC_FILLMEM | PROC_FILLSTAT | PROC_FILLUSR); //获取进程和用户信息
	#ifdef STEP
	getchar();
	#endif
	write(txt_fd, "\n", 1);
	ShowFormat(0, FormatMake(STATES_line1, Frame_maxtask, Frame_running, Frame_sleepin, Frame_stopped, Frame_zombied)); //进程信息汇总
	char *_p = _buf; 
	write(txt_fd, _p, strlen(_p));
#ifdef TEST
   getchar();
#endif
	row_to_show++;
	smpcpu = CpusRead(smpcpu); //获取cpu运行在各个状态的jiffies
	#ifdef STEP
	getchar();
	#endif
	#ifdef STEP
	getchar();
	#endif
	summaryhlp(&smpcpu[Cpu_tot], "Cpu(s):"); //展示cpu使用情况

	MemRead(); //读取/proc/meminfo下的内存汇总信息
	ShowFormat(0, FormatMake(MEMORY_line1, kb_main_total, kb_main_used, kb_main_free, kb_main_buffers));
	_p = _buf;
	write(txt_fd, _p, strlen(_p));
#ifdef TEST
   getchar();
#endif
	row_to_show++;
	#ifdef STEP
	getchar();
	#endif
    ShowFormat(0, FormatMake(MEMORY_line2, kb_swap_total, kb_swap_used, kb_swap_free, kb_main_cached));
	_p = _buf;
	write(txt_fd, _p, strlen(_p));
#ifdef TEST
   getchar();
#endif
	row_to_show++;
	NetRead();
	NetTitleShow();
	NetShow();
	write(txt_fd, "\n\n\n\tuser information\n", strlen("\n\n\n\tuser information\n"));
	write(txt_fd, "\n\tcpu\tmem\n", strlen("\n\tcpu\tmem\n"));
	user_p temp = &user_head;
	while(temp->next != NULL){ //展示用户资源使用
		write(txt_fd, temp->next->name, strlen(temp->next->name));
		write(txt_fd, "\t", 1);
		write(txt_fd, temp->next->cpu, strlen(temp->next->cpu));
		write(txt_fd, "\t", 1);
		write(txt_fd, temp->next->mem, strlen(temp->next->mem));
		write(txt_fd, "\n", 1);
		temp = temp->next;
	}
	process_p process = &process_head;
	process_p to_free;
	char process_buf[200];
	while(process->next != NULL){ //展示存活的进程 在生命周期的平均资源使用情况
		if(process->next->alive == 1){
			process->next->alive = 0;
		}
		else{
			sprintf(process_buf, "cmd:%s\tcpu:%ujiffies\tmem(average):%ldKB\tswap(average):%ldKB\tread:%s\twrite:%s\n", process->next->cmd, process->next->cput, process->next->memt / process->next->seconds, process->next->swap / process->next->seconds, process->next->rchar, process->next->wchar);
			write(proc_fd, process_buf, strlen(process_buf));
			to_free = process->next;
			process->next = process->next->next;
			free(to_free);	
		}
		process = process->next;
		if(NULL == process){
			break;
		}
	}
	return p_table;
}	

void TaskShow(proc_t *task){
	if(row_to_show > lines) return;
	putp(tgoto(cursor_address, 0, row_to_show));
	//ShowFormat(0, FormatMake(TASK_line, task->tid, task->pcpu, task->size, task->vm_size, task->euser, task->utime, task->vm_exe, task->vm_data + task->vm_stack, task->ppid, task->ruser, task->egroup, task->cmdline));
	if(task->pcpu / 100 > 1000){
		putp(clr_eol);
		SHOW_TASK1
	}
	else{
		putp(clr_eol);
		SHOW_TASK0
	}
}

void TaskTitleShow(){
	putp(tgoto(cursor_address, 0, row_to_show));
	ShowFormat(0, TASK_TITLE);
	write(txt_fd, TASK_TITLE, strlen(TASK_TITLE));
	write(txt_fd, "\n", 1);
#ifdef TEST
   getchar();
#endif
}

void MessageShow(char *message){
	putp(tgoto(cursor_address, 0, 1));
	putp(clr_eol);
	ShowFormat(0, message);
	putp(tgoto(cursor_address, 0, row_to_show));
}

int readLine(int fd){
	int i = 0;
	do{
		if(read(fd, line_buf[i], 1) == 0){
			line_buf[i] = 0;
			return 0;	//后面没了
		}
	}while(line_buf[i++] != '\n');
	return 1;	//后面还有
}

void init(void){
	setupterm(NULL, STDOUT_FILENO, NULL);
	putp(clear_screen); // 这些变量的信息可在 term.h 和 man terminfo 中查到
	putp(cursor_invisible);
	putp("This is for test\ncol1\ncol2\n");
	Cpu_tot = sysconf(_SC_NPROCESSORS_ONLN); //获取cpu核心数目
	MessageShow("Message:init complete");
	getchar();
	txt_fd = open("/usr/local/nginx/html/test/test.txt", O_WRONLY, 0); //网页展示用的文件
	proc_fd = open("/usr/local/nginx/html/test/proc.txt", O_WRONLY, 0);
	if(txt_fd == -1) return -1;
	if(proc_fd == -1) return -1;
	user_head.next = NULL;
	user_tail = &user_head;
	process_head.next = NULL;
	process_tail = &process_head;
}

void frame(void){
	ftruncate(txt_fd, 0); //fd指定的文件大小改为参数length指定的大小 此处作用就是清空
	lseek(txt_fd, 0, SEEK_SET);
	lseek(proc_fd, 0, SEEK_END);
	putp(tgoto(cursor_address, 0, 3));
	char a = '\0';
	printf("%s\n", &a);
	row_to_show = 3;
	user_p temp = &user_head;
	user_p pre;
	while(temp->next != NULL){
		pre = temp->next;
		free(pre);
		temp = temp->next;
	}
	user_head.next = NULL;
	summary_show();
	//putp(clr_eol);
	//strcat(str,"AS");
	//str[0] += 1;
	//putp(str);
	//putp(clr_eos);
}
