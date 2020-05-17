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

#include "_UPT_internal.h"

void
free_mem_region(struct proc_info* info)
{
    for (int i = 0; i < MAX_REGIONS; i++)
    {
        free(info->regions[i].data);
        info->regions[i].data = NULL;
    }
    info->num_regions = 0;
}

void
destroy_proc_info(struct proc_info* info)
{
    free_mem_region(info);
    fclose(info->map_fp);
    close(info->mem_fd);

    // print some statics
    fprintf(stderr, "==================, invocations = %d, mem_access= %d, read,lseek = %d",
               info->num_invocation, info->num_memaccess, info->num_read_lseek);
}

void
_UPT_destroy (void *ptr)
{

  destroy_proc_info((struct proc_info *)ptr);
  struct UPT_info *ui = (struct UPT_info *) ptr;
  invalidate_edi (&ui->edi);
  free (ptr);
}
