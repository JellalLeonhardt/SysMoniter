#include "common.h"

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

#define LOADAV_line  "%s -%s\n"
#define LOADAV_line_alt  "%s\06 -%s\n"
#define STATES_line1  "Tasks:\03" \
   " %3u \02total,\03 %3u \02running,\03 %3u \02sleeping,\03 %3u \02stopped,\03 %3u \02zombie\03\n"
#define STATES_line2x4  "%s\03" \
   " %#5.1f%% \02user,\03 %#5.1f%% \02system,\03 %#5.1f%% \02nice,\03 %#5.1f%% \02idle\03\n"
#define STATES_line2x5  "%s\03" \
   " %#5.1f%% \02user,\03 %#5.1f%% \02system,\03 %#5.1f%% \02nice,\03 %#5.1f%% \02idle,\03 %#5.1f%% \02IO-wait\03\n"
#define STATES_line2x6  "%s\03" \
   " %#4.1f%% \02us,\03 %#4.1f%% \02sy,\03 %#4.1f%% \02ni,\03 %#4.1f%% \02id,\03 %#4.1f%% \02wa,\03 %#4.1f%% \02hi,\03 %#4.1f%% \02si\03\n"
#define STATES_line2x7  "%s\03" \
   "%#5.1f%%\02us,\03%#5.1f%%\02sy,\03%#5.1f%%\02ni,\03%#5.1f%%\02id,\03%#5.1f%%\02wa,\03%#5.1f%%\02hi,\03%#5.1f%%\02si,\03%#5.1f%%\02st\03\n"
#ifdef CASEUP_SUMMK
#define MEMORY_line1  "Mem: \03" \
   " %8luK \02total,\03 %8luK \02used,\03 %8luK \02free,\03 %8luK \02buffers\03\n"
#define MEMORY_line2  "Swap:\03" \
   " %8luK \02total,\03 %8luK \02used,\03 %8luK \02free,\03 %8luK \02cached\03\n"
#else
#define MEMORY_line1  "Mem: \03" \
   " %8luk \02total,\03 %8luk \02used,\03 %8luk \02free,\03 %8luk \02buffers\03\n"
#define MEMORY_line2  "Swap:\03" \
   " %8luk \02total,\03 %8luk \02used,\03 %8luk \02free,\03 %8luk \02cached\03\n"
#endif

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

typedef unsigned long long TIC_t;
typedef          long long SIC_t;

typedef struct PROCTAB {
	    DIR*	procfs;
		DIR*	taskdir;  // for threads
		pid_t	taskdir_user;  // for threads
		int         did_fake; // used when taskdir is missing
		int(*finder)(struct PROCTAB *restrict const, proc_t *restrict const);
		proc_t*(*reader)(struct PROCTAB *restrict const, proc_t *restrict const);
		int(*taskfinder)(struct PROCTAB *restrict const, const proc_t *restrict const, proc_t *restrict const, char *restrict const);
		proc_t*(*taskreader)(struct PROCTAB *restrict const, const proc_t *restrict const, proc_t *restrict const, char *restrict const);
		pid_t*	pids;	// pids of the procs
		uid_t*	uids;	// uids of procs
		int		nuid;	// cannot really sentinel-terminate unsigned short[]
		int         i;  // generic
		unsigned	flags;
		unsigned    u;  // generic
		void *      vp; // generic
		char        path[PROCPATHLEN];  // must hold /proc/2000222000/task/2000222000/cmdline
		unsigned pathlen;        // length of string in the above (w/o '\0')
};

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
	char name[P_G_SZ];
} *pwhash[HASHSIZE];

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

static char str[100] = " ";

static int proc_table_size;

static int Cpu_tot;

extern void __cyg_profile_func_enter(void*, void*);
extern void	__cyg_profile_func_exit(void *, void *);

static void show_special(int interact, const char *glob);

static const char *fmtmk (const char *fmts, ...)
{
   static char buf[BIGBUFSIZ];          // with help stuff, our buffer
   va_list va;                          // requirements exceed 1k

   va_start(va, fmts);
   vsnprintf(buf, sizeof(buf), fmts, va);
   va_end(va);
   return (const char *)buf;
}

static int simple_nexttid(PROCTAB *restrict const PT, const proc_t *restrict const p, proc_t *restrict const t, char *restrict const path) {
	static struct direct *ent;		/* dirent handle */
	if(PT->taskdir_user != p->tgid){
		    if(PT->taskdir){
				closedir(PT->taskdir);
			}
	    	snprintf(path, PROCPATHLEN, "/proc/%d/task", p->tgid);
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
	snprintf(path, PROCPATHLEN, "/proc/%d/task/%s", p->tgid, ent->d_name);
	return 1;
}

static int file2str(const char *directory, const char *what, char *ret, int cap){
	static char filename[80];
	int fd, num_read;

	sprintf(filename, "%s/%s", directory, what);
	fd = open(filename, O_READONLY, 0);
	if(fd == -1) return -1;
	num_read = read(fd, ret, cap - 1);
	close(fd);
	if(num_read <= 0) return -1;
	ret[num_read] = '\0';
	return num_read;
}

static void stat2proc(const char *S, proc_t *restrict P){
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
		p->nlwp = 1;
	}

	__cyg_profile_func_exit((void *)0x160, (void *)0x160);
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
	if(!pw || strlen(pw->pw_name) >= P_G_SZ)
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
	if (!gr || strlen(gr->gr_name) >= P_G_SZ)
	    sprintf((*g)->name, "%u", gid);
	else
	        strcpy((*g)->name, gr->gr_name);
	(*g)->next = NULL;
	return((*g)->name);
}

static proc_t* simple_readtask(PROCTAB *restrict const PT, const proc_t *restrict const p, proc_t *restrict const t, char *restrict const path) {
	    static struct stat sb;		// stat() buffer
		static char sbuf[1024];	// buffer for stat,statm
		unsigned flags = PT->flags;

		if(stat(path, &b) == -1){
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
				memcpy(t->rgroupe, user_frome_uid(t->euid), sizeof(t->euser));
				memcpy(t->sgroupe, user_frome_uid(t->suid), sizeof(t->suser));
				memcpy(t->fgroupe, user_frome_uid(t->fuid), sizeof(t->fuser));
			}
		}

		if(flags & 0x0010){
			memcpy(t->euser, user_from_uid(t->euid), sizeof(t->euser));
			if(flags & 0x0020){
				memcpy(t->rgroupe, user_frome_uid(t->euid), sizeof(t->euser));
				memcpy(t->sgroupe, user_frome_uid(t->suid), sizeof(t->suser));
				memcpy(t->fgroupe, user_frome_uid(t->fuid), sizeof(t->fuser));
			}
		}

		t->cmdline = P->cmdline;
		t->environ = P->environ;
		t->ppid = P->ppid;
		return t;
next_task:
		return NULL;
}

static proc_t* simple_readproc(PROCTAB *restrict const PT, proc_t *restrict const p) {
	static struct stat sb;		// stat() buffer
	static char sbuf[1024];	// buffer for stat,statm
	char *restrict const path = PT->path;
	unsigned flags = PT->flags;

	if (stat(path, &sb) == -1)	/* no such dirent (anymore) */
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

	// if multithreaded, some values are crap
    if(p->nlwp > 1){
      p->wchan = (KLONG)~0ull;
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

static int listed_nextpid(PROCTAB *restrict const PT, proc_t *restrict const p) {
  char *restrict const path = PT->path;
  pid_t tgid = *(PT->pids)++;
  if( tgid ){
    snprintf(path, PROCPATHLEN, "/proc/%d", tgid);
    p->tgid = tgid;
    p->tid = tgid;  // they match for leaders
  }
  return tgid;
}

static int simple_nextpid(PROCTAB *restrict const PT, proc_t *restrict const p) {
  static struct direct *ent;		/* dirent handle */
  char *restrict const path = PT->path;
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


PROCTAB *openproc(int flags){	//可变参数那部分删除
	PROCTAB *PT = malloc(sizeof(PROCTAB));

	PT->taskdir = NULL;
	PT->taskdir_user = -1;
	PT->taskfinder = simple_nextid;
	PT->taskreader = simple_readtask;

	PT->reader = simple_readproc;
	if (flags & 0x1000){
      PT->procfs = NULL;
      PT->finder = listed_nextpid;
    }else{
      PT->procfs = opendir("/proc");
      if(!PT->procfs) return NULL;
      PT->finder = simple_nextpid;
    }
    PT->flags = flags;

    return PT;
}

proc_t* readproc(PROCTAB *restrict const PT, proc_t *restrict p) {
  proc_t *ret;
  proc_t *saved_p;

  PT->did_fake=0;
//  if (PT->taskdir) {
//    closedir(PT->taskdir);
//    PT->taskdir = NULL;
//    PT->taskdir_user = -1;
//  }

  saved_p = p;
  if(!p) p = (proc_t *)malloc(p, sizeof *p); /* passed buf or alloced mem */

  for(;;){
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

static void prochlp (proc_t *this)
{
   static HST_t    *hist_sav = NULL;
   static HST_t    *hist_new = NULL;
   static unsigned  hist_siz = 0;       // number of structs
   static unsigned  maxt_sav;           // prior frame's max tasks
   TIC_t tics;

   if (!this) {
      static struct timeval oldtimev;
      struct timeval timev;
      struct timezone timez;
      HST_t *hist_tmp;
      float et;

      gettimeofday(&timev, &timez);
      et = (timev.tv_sec - oldtimev.tv_sec)
         + (float)(timev.tv_usec - oldtimev.tv_usec) / 1000000.0;
      oldtimev.tv_sec = timev.tv_sec;
      oldtimev.tv_usec = timev.tv_usec;

      // if in Solaris mode, adjust our scaling for all cpus
      Frame_tscale = 100.0f / ((float)Hertz * (float)et * (Rc.mode_irixps ? 1 : Cpu_tot));
      maxt_sav = Frame_maxtask;
      Frame_maxtask = Frame_running = Frame_sleepin = Frame_stopped = Frame_zombied = 0;

      // reuse memory each time around
      hist_tmp = hist_sav;
      hist_sav = hist_new;
      hist_new = hist_tmp;
      // prep for our binary search by sorting the last frame's HST_t's
      qsort(hist_sav, maxt_sav, sizeof(HST_t), (QFP_t)sort_HST_t);
      return;
   }

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
   if(ptr) tics -= ptr->tics;

   // we're just saving elapsed tics, to be converted into %cpu if
   // this task wins it's displayable screen row lottery... */
   this->pcpu = tics;
// if (Frames_maxcmdln) { }
   // shout this to the world with the final call (or us the next time in)
   Frame_maxtask++;
}

static void summaryhlp (CPU_t *cpu, const char *pfx)
{
   // we'll trim to zero if we get negative time ticks,
   // which has happened with some SMP kernels (pre-2.4?)
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
   show_special(
      0,
      fmtmk(
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

static proc_t **procs_refresh (proc_t **table, int flags){
	PROCTAB *PT = PT = openproc(flags);
	proc_t *ptsk;
	int idx;

	if(table == NULL){
		proc_table_size = 10;
		table = (proc_t **)malloc(sizeof(proc_t *) * 10);
	}

	while(1){
		if((ptsk = readproc(PT, NULL)) != NULL){
			prochlp(ptsk);
			table[idx++] = ptsk;
			if(idx == proc_table_size){
				proc_table_size = proc_table_size * 2;
				table = (proc_t **)realloc(table, sizeof(proc_t *) * proc_table_size);
			}
		}
		else{
			break;
		}
	}
	return table;
		
}

static CPU_t *cpus_refresh (CPU_t *cpus)
{
   static FILE *fp = NULL;
   int i;
   int num;
   // enough for a /proc/stat CPU line (not the intr line)
   char buf[SMLBUFSIZ];

   /* by opening this file once, we'll avoid the hit on minor page faults
      (sorry Linux, but you'll have to close it for us) */
   if (!fp) {
      if (!(fp = fopen("/proc/stat", "r")))
         std_err(fmtmk("Failed /proc/stat open: %s", strerror(errno)));
      /* note: we allocate one more CPU_t than Cpu_tot so that the last slot
               can hold tics representing the /proc/stat cpu summary (the first
               line read) -- that slot supports our View_CPUSUM toggle */
      cpus = (CPU_t *)realloc((1 + Cpu_tot) * sizeof(CPU_t));
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

void meminfo(void){
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

  FILE_TO_BUF(MEMINFO_FILE,meminfo_fd);

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

static void show_special(int interact, const char *glob){
	char *line_end, line[2048];
	long long cols;
	while((line_end = strchr(glob, '\n')) != NULL){
		cols = line_end - glob;
		memcpy(line, glob, cols);
		line[cols] = '\0';
		if (interact) PUTT("%s%s\n", row, clr_eol);
      	else PUFF("%s%s\n", row, clr_eol);
		glob = line_end + 1;
	}
	if (*glob) PUTT("%s", glob);
}

static proc_t **summary_show (void){
	static proc_t **p_table = NULL;
	static CPU_t *smpcpu = NULL;

	if(!p_table){
		p_table = procs_refresh(NULL, 0);
	}
	else{
		p_table = procs_refresh(p_table, 0;
	}

	smpcpu = cpus_refresh(smpcpu);
	
	show_special(0, fmtmk(STATES_line1, Frame_maxtask, Frame_running, Frame_sleepin, Frame_stopped, Frame_zombied));

	summaryhlp(&smpcpu[Cpu_tot], "Cpu(s):");

	meminfo();
	show_special(0, fmtmk(MEMORY_line1, kb_main_total, kb_main_used, kb_main_free, kb_main_buffers));
    show_special(0, fmtmk(MEMORY_line2, kb_swap_total, kb_swap_used, kb_swap_free, kb_main_cached));

	return p_table;
}	

void init(void){
	setupterm(NULL, STDOUT_FILENO, NULL);
	putp(clear_screen);
	putp("This is for test\ncol1\ncol2\n");
	Cpu_tot = sysconf(_SC_NPROCESSORS_ONLN);
	getchar();
}

void sysInfo(void){

}

void taskInfo(void){

}

void frame(void){
	putp(tgoto(cursor_address, 0, 3));
	//putp(clear_screen);
	putp(clr_eol);
	strcat(str,"AS");
	str[0] += 1;
	putp(str);
	putp(clr_eos);
}
