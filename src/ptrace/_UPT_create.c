/* libunwind - a platform-independent unwind library
   Copyright (C) 2003 Hewlett-Packard Co
        Contributed by David Mosberger-Tang <davidm@hpl.hp.com>

This file is part of libunwind.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.  */

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "_UPT_internal.h"

void
init_proc_info(struct proc_info* info, int pid)
{
    // initialize them with invalid
    sprintf(info->map_path, "/proc/%d/maps", pid);
    sprintf(info->mem_path, "/proc/%d/mem", pid);
    fprintf(stderr, "map path is: %s\n", info->map_path);
    fprintf(stderr, "mem path is: %s\n", info->mem_path);
    info->num_regions = 0;
    fprintf(stderr, "size of regions = %ld", sizeof(info->regions));
    memset(&(info->regions), 0, sizeof(info->regions));

    info->map_fp = fopen(info->map_path, "r");
    if (!info->map_fp) {
        fprintf(stderr, "Open maps");
        return;
    }

    info->mem_fd = open(info->mem_path, O_RDONLY);
    if (info->mem_fd < 0) {
        fprintf(stderr, "Open mem file");
    }

}

void *
_UPT_create (pid_t pid)
{
  struct UPT_info *ui = malloc (sizeof (struct UPT_info));

  if (!ui)
    return NULL;

  memset (ui, 0, sizeof (*ui));
  ui->pid = pid;
  ui->edi.di_cache.format = -1;
  ui->edi.di_debug.format = -1;
#if UNW_TARGET_IA64
  ui->edi.ktab.format = -1;
#endif
  void* r = realloc(r, sizeof(struct proc_info));
  struct proc_info* info = (struct proc_info*)r;
  init_proc_info(info, pid);

  return info;
}
