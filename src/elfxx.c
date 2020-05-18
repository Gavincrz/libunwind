/* libunwind - a platform-independent unwind library
   Copyright (C) 2003-2005 Hewlett-Packard Co
   Copyright (C) 2007 David Mosberger-Tang
        Contributed by David Mosberger-Tang <dmosberger@gmail.com>

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

#include "libunwind_i.h"

#include <stdio.h>
#include <sys/param.h>
#include <limits.h>

#ifdef HAVE_LZMA
#include <lzma.h>
#endif /* HAVE_LZMA */


static Elf_W (Shdr)*
elf_w (section_table) (struct elf_image *ei)
{
  Elf_W (Ehdr) *ehdr = ei->image;
  Elf_W (Off) soff;

  soff = ehdr->e_shoff;
  if (soff + ehdr->e_shnum * ehdr->e_shentsize > ei->size)
    {
      Debug (1, "section table outside of image? (%lu > %lu)\n",
             (unsigned long) (soff + ehdr->e_shnum * ehdr->e_shentsize),
             (unsigned long) ei->size);
      return NULL;
    }

  return (Elf_W (Shdr) *) ((char *) ei->image + soff);
}

static char*
elf_w (string_table) (struct elf_image *ei, int section)
{
  Elf_W (Ehdr) *ehdr = ei->image;
  Elf_W (Off) soff, str_soff;
  Elf_W (Shdr) *str_shdr;

  /* this offset is assumed to be OK */
  soff = ehdr->e_shoff;

  str_soff = soff + (section * ehdr->e_shentsize);
  if (str_soff + ehdr->e_shentsize > ei->size)
    {
      Debug (1, "string shdr table outside of image? (%lu > %lu)\n",
             (unsigned long) (str_soff + ehdr->e_shentsize),
             (unsigned long) ei->size);
      return NULL;
    }
  str_shdr = (Elf_W (Shdr) *) ((char *) ei->image + str_soff);

  if (str_shdr->sh_offset + str_shdr->sh_size > ei->size)
    {
      Debug (1, "string table outside of image? (%lu > %lu)\n",
             (unsigned long) (str_shdr->sh_offset + str_shdr->sh_size),
             (unsigned long) ei->size);
      return NULL;
    }

  Debug (16, "strtab=0x%lx\n", (long) str_shdr->sh_offset);
  return ei->image + str_shdr->sh_offset;
}


static int
lookup_symbol_in_cache (unw_word_t ip, struct image_cache_entry_t* cache_entry,
                       Elf_W (Addr) load_offset,
                       char *buf, size_t buf_len, Elf_W (Addr) *min_dist)
{
    Elf_W (Addr) val;
    Elf_W (Half) st_shndx;
    char* name;
    int i, ret = -UNW_ENOINFO;
    for (i = 0; i < cache_entry->num_symbol; i++) {
        st_shndx = cache_entry->symbol_table[i].st_shndx;
        val = cache_entry->symbol_table[i].val;
        name = cache_entry->symbol_table[i].name;

        if (st_shndx != SHN_ABS)
            val += load_offset;
        if (tdep_get_func_addr (as, val, &val) < 0){
            fprintf(stderr, "How coud this happen???\n");
            continue;
        }

        if ((Elf_W (Addr)) (ip - val) < *min_dist)
        {
            *min_dist = (Elf_W (Addr)) (ip - val);
            strncpy (buf, name, buf_len);
            buf[buf_len - 1] = '\0';
            ret = (strlen (name) >= buf_len
               ? -UNW_ENOMEM : 0);
        }


    }

    return ret;
}

static void
clear_symbol_table (struct image_cache_entry_t* cache_entry){
    for (int i = 0; i < MAX_FN_SYM; i++) {
        cache_entry->symbol_table[i].name = NULL;
        cache_entry->symbol_table[i].val = 0;
        cache_entry->symbol_table[i].st_shndx = 0;
    }
    cache_entry->num_symbol = 0;
}

static int
load_fn_symbol_table (unw_addr_space_t as, struct image_cache_entry_t* cache_entry)
{
    struct elf_image *ei = &(cache_entry->ei);
    size_t syment_size;
    Elf_W (Ehdr) *ehdr = ei->image;
    Elf_W (Sym) *sym, *symtab, *symtab_end;
    Elf_W (Shdr) *shdr;
    Elf_W (Addr) val;
    int i, ret = -UNW_ENOINFO;
    char *strtab;

    if (!elf_w (valid_object) (ei))
        return -UNW_ENOINFO;

    shdr = elf_w (section_table) (ei);
    if (!shdr)
        return -UNW_ENOINFO;

    int symbol_count = 0;

    for (i = 0; i < ehdr->e_shnum; ++i)
    {
        switch (shdr->sh_type)
        {
            case SHT_SYMTAB:
            case SHT_DYNSYM:
                symtab = (Elf_W (Sym) *) ((char *) ei->image + shdr->sh_offset);
                symtab_end = (Elf_W (Sym) *) ((char *) symtab + shdr->sh_size);
                syment_size = shdr->sh_entsize;

                strtab = elf_w (string_table) (ei, shdr->sh_link);
                if (!strtab)
                    break;

                for (sym = symtab;
                     sym < symtab_end;
                     sym = (Elf_W (Sym) *) ((char *) sym + syment_size))
                {
                    if (ELF_W (ST_TYPE) (sym->st_info) == STT_FUNC
                        && sym->st_shndx != SHN_UNDEF)
                    {
                        if (symbol_count >= MAX_FN_SYM) {
                            fprintf(stderr, "number of symbol count(%d) > MAX_FN_SYM, please increase it\n",
                                    symbol_count);
                            assert(0);
                        }
                        // found one symbol, record in symbol table cache
                        val = sym->st_value;
                        cache_entry->symbol_table[symbol_count].st_shndx = sym->st_shndx;
                        cache_entry->symbol_table[symbol_count].val = val;
                        cache_entry->symbol_table[symbol_count].name = strtab + sym->st_name;
                        symbol_count++;
                    }
                }
                break;

            default:
                break;
        }
        shdr = (Elf_W (Shdr) *) (((char *) shdr) + ehdr->e_shentsize);
    }
    cache_entry->num_symbol = symbol_count;
    return ret;
}

static int
elf_w (lookup_symbol) (unw_addr_space_t as,
                       unw_word_t ip, struct elf_image *ei,
                       Elf_W (Addr) load_offset,
                       char *buf, size_t buf_len, Elf_W (Addr) *min_dist)
{
  size_t syment_size;
  Elf_W (Ehdr) *ehdr = ei->image;
  Elf_W (Sym) *sym, *symtab, *symtab_end;
  Elf_W (Shdr) *shdr;
  Elf_W (Addr) val;
  int i, ret = -UNW_ENOINFO;
  char *strtab;

  if (!elf_w (valid_object) (ei))
    return -UNW_ENOINFO;

  shdr = elf_w (section_table) (ei);
  if (!shdr)
    return -UNW_ENOINFO;

  int num_func_symbol = 0;
  for (i = 0; i < ehdr->e_shnum; ++i)
    {
      switch (shdr->sh_type)
        {
        case SHT_SYMTAB:
        case SHT_DYNSYM:
          symtab = (Elf_W (Sym) *) ((char *) ei->image + shdr->sh_offset);
          symtab_end = (Elf_W (Sym) *) ((char *) symtab + shdr->sh_size);
          syment_size = shdr->sh_entsize;

          strtab = elf_w (string_table) (ei, shdr->sh_link);
          if (!strtab)
            break;

          Debug (16, "symtab=0x%lx[%d]\n",
                 (long) shdr->sh_offset, shdr->sh_type);

          for (sym = symtab;
               sym < symtab_end;
               sym = (Elf_W (Sym) *) ((char *) sym + syment_size))
            {
              if (ELF_W (ST_TYPE) (sym->st_info) == STT_FUNC
                  && sym->st_shndx != SHN_UNDEF)
                {
                  num_func_symbol++;
                  val = sym->st_value;
                  if (sym->st_shndx != SHN_ABS)
                    val += load_offset;
                  if (tdep_get_func_addr (as, val, &val) < 0)
                    continue;
                  Debug (16, "0x%016lx info=0x%02x %s\n",
                         (long) val, sym->st_info, strtab + sym->st_name);

                  if ((Elf_W (Addr)) (ip - val) < *min_dist)
                    {
                      *min_dist = (Elf_W (Addr)) (ip - val);
                      strncpy (buf, strtab + sym->st_name, buf_len);
                      buf[buf_len - 1] = '\0';
                      ret = (strlen (strtab + sym->st_name) >= buf_len
                             ? -UNW_ENOMEM : 0);
                    }
                }
            }
          break;

        default:
          break;
        }
      shdr = (Elf_W (Shdr) *) (((char *) shdr) + ehdr->e_shentsize);
    }
  return ret;
}



static Elf_W (Addr)
elf_w (get_load_offset) (struct elf_image *ei, unsigned long segbase,
                         unsigned long mapoff)
{
  Elf_W (Addr) offset = 0;
  Elf_W (Ehdr) *ehdr;
  Elf_W (Phdr) *phdr;
  int i;

  ehdr = ei->image;
  phdr = (Elf_W (Phdr) *) ((char *) ei->image + ehdr->e_phoff);

  for (i = 0; i < ehdr->e_phnum; ++i)
    if (phdr[i].p_type == PT_LOAD && phdr[i].p_offset == mapoff)
      {
        offset = segbase - phdr[i].p_vaddr;
        break;
      }

  return offset;
}

#if HAVE_LZMA
static size_t
xz_uncompressed_size (uint8_t *compressed, size_t length)
{
  uint64_t memlimit = UINT64_MAX;
  size_t ret = 0, pos = 0;
  lzma_stream_flags options;
  lzma_index *index;

  if (length < LZMA_STREAM_HEADER_SIZE)
    return 0;

  uint8_t *footer = compressed + length - LZMA_STREAM_HEADER_SIZE;
  if (lzma_stream_footer_decode (&options, footer) != LZMA_OK)
    return 0;

  if (length < LZMA_STREAM_HEADER_SIZE + options.backward_size)
    return 0;

  uint8_t *indexdata = footer - options.backward_size;
  if (lzma_index_buffer_decode (&index, &memlimit, NULL, indexdata,
                                &pos, options.backward_size) != LZMA_OK)
    return 0;

  if (lzma_index_size (index) == options.backward_size)
    {
      ret = lzma_index_uncompressed_size (index);
    }

  lzma_index_end (index, NULL);
  return ret;
}

static int
elf_w (extract_minidebuginfo) (struct elf_image *ei, struct elf_image *mdi)
{
  Elf_W (Shdr) *shdr;
  uint8_t *compressed = NULL;
  uint64_t memlimit = UINT64_MAX; /* no memory limit */
  size_t compressed_len, uncompressed_len;

  shdr = elf_w (find_section) (ei, ".gnu_debugdata");
  if (!shdr)
    return 0;

  compressed = ((uint8_t *) ei->image) + shdr->sh_offset;
  compressed_len = shdr->sh_size;

  uncompressed_len = xz_uncompressed_size (compressed, compressed_len);
  if (uncompressed_len == 0)
    {
      Debug (1, "invalid .gnu_debugdata contents\n");
      return 0;
    }

  mdi->size = uncompressed_len;
  mdi->image = mmap (NULL, uncompressed_len, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

  if (mdi->image == MAP_FAILED)
    return 0;

  size_t in_pos = 0, out_pos = 0;
  lzma_ret lret;
  lret = lzma_stream_buffer_decode (&memlimit, 0, NULL,
                                    compressed, &in_pos, compressed_len,
                                    mdi->image, &out_pos, mdi->size);
  if (lret != LZMA_OK)
    {
      Debug (1, "LZMA decompression failed: %d\n", lret);
      munmap (mdi->image, mdi->size);
      return 0;
    }

  return 1;
}
#else
static int
elf_w (extract_minidebuginfo) (struct elf_image *ei, struct elf_image *mdi)
{
  return 0;
}
#endif /* !HAVE_LZMA */

/* Find the ELF image that contains IP and return the "closest"
   procedure name, if there is one.  With some caching, this could be
   sped up greatly, but until an application materializes that's
   sensitive to the performance of this routine, why bother...  */

HIDDEN int
elf_w (get_proc_name_in_image) (unw_addr_space_t as, struct elf_image *ei,
                       unsigned long segbase,
                       unsigned long mapoff,
                       unw_word_t ip,
                       char *buf, size_t buf_len, unw_word_t *offp)
{
  Elf_W (Addr) load_offset;
  Elf_W (Addr) min_dist = ~(Elf_W (Addr))0;
  int ret;

  load_offset = elf_w (get_load_offset) (ei, segbase, mapoff);
  ret = elf_w (lookup_symbol) (as, ip, ei, load_offset, buf, buf_len, &min_dist);

  /* If the ELF image has MiniDebugInfo embedded in it, look up the symbol in
     there as well and replace the previously found if it is closer. */
  struct elf_image mdi;
  if (elf_w (extract_minidebuginfo) (ei, &mdi))
    {
      int ret_mdi = elf_w (lookup_symbol) (as, ip, &mdi, load_offset, buf,
                                           buf_len, &min_dist);

      /* Closer symbol was found (possibly truncated). */
      if (ret_mdi == 0 || ret_mdi == -UNW_ENOMEM)
        {
          ret = ret_mdi;
        }

      munmap (mdi.image, mdi.size);
    }

  if (min_dist >= ei->size)
    return -UNW_ENOINFO;                /* not found */
  if (offp)
    *offp = min_dist;
  return ret;
}

HIDDEN int
elf_w (get_proc_name_in_cache) (unw_addr_space_t as,
                                pid_t pid,
                                const char* file,
                                unsigned long segbase,
                                unsigned long mapoff,
                                unw_word_t ip,
                                char *buf, size_t buf_len, unw_word_t *offp,
                                struct proc_info *info)
{
    Elf_W (Addr) load_offset;
    Elf_W (Addr) min_dist = ~(Elf_W (Addr))0;
    int ret;

    // find file in cache
    struct image_cache_entry_t *entries = info->image_cache;
    struct image_cache_entry_t *cache_entry = NULL;
    for (int i = 0; i < info->num_image_cache; i++) {
        struct image_cache_entry_t* temp_entry = &(entries[i]);
        if (strcmp(file, temp_entry->binary_filename) == 0)
            cache_entry = temp_entry;
    }
    if (cache_entry == NULL)
    {
        // load the cache_entry

        cache_entry = &(entries[info->num_image_cache]);

        // load the file name
        strcpy(cache_entry->binary_filename, file);

        // load the ei image
        ret = elf_map_image (&(cache_entry->ei), file);
        cache_entry->ei_time = cache_entry->ei.mtime;
        if (ret < 0)
            return ret;

        cache_entry->ei.mtime = 0; //reload every time
        // load debug ei
        ret = elf_w(load_debuglink)(file, &(cache_entry->ei), 1);
        if (ret < 0)
            return ret;

        cache_entry->debug_time = cache_entry->ei.mtime;

        // load the symbol table
        load_fn_symbol_table(as, cache_entry);

        info->num_image_cache++;
    }

    if (cache_entry->need_update) {
//        fprintf(stderr, "need update!! for file %s\n", file);
//        time_t saved_debug_time = cache_entry->debug_time;
//        time_t saved_ei_time = cache_entry->ei_time;
//        cache_entry->ei.mtime = cache_entry->ei_time;
//
//        cache_entry->ei.mtime = 0;
        // load the ei image
        munmap(cache_entry->ei.image, cache_entry->ei.size);
        ret = elf_map_image (&(cache_entry->ei), file);
        if (ret < 0)
            return ret;
//
//        cache_entry->ei_time = cache_entry->ei.mtime;
//
//        // reload the debug ei
//        cache_entry->ei.mtime = cache_entry->debug_time;
//
//        if (saved_ei_time != cache_entry->ei_time) {
//            cache_entry->ei.mtime = 0;
//        }
//
//        cache_entry->ei.mtime = 0;
        ret = elf_w(load_debuglink)(file, &(cache_entry->ei), 1);
        if (ret < 0)
            return ret;
//        cache_entry->debug_time = cache_entry->ei.mtime;

//        if (saved_debug_time != cache_entry->debug_time || saved_ei_time != cache_entry->ei_time) {
//            fprintf(stderr, "debug file has been changed!!!\n");
            // clear symbol table
            clear_symbol_table(cache_entry);
            // load the symbol table
            load_fn_symbol_table(as, cache_entry);
//        }

        cache_entry->need_update = false;
    }


    struct elf_image *ei = &(cache_entry->ei);
    assert(ei->image);


    load_offset = elf_w (get_load_offset) (ei, segbase, mapoff);

    ret = lookup_symbol_in_cache (ip, cache_entry, load_offset, buf, buf_len, &min_dist);


//    ret = elf_w (load_debuglink) (file, &ei, 1);
//
//    if (ret < 0)
//        return ret;
//
//    ret = elf_w (get_proc_name_in_image) (as, &ei, segbase, mapoff, ip, buf, buf_len, offp);

//    munmap (ei->image, ei->size);
//    ei->image = NULL;

    if (offp)
        *offp = min_dist;
    return ret;
}

void
clear_cache (struct proc_info *info)
{
    struct image_cache_entry_t *entries = info->image_cache;
    size_t cache_size = sizeof(struct image_cache_entry_t) * MAX_REGIONS;

    for (int i = 0; i < info->num_image_cache; i++) {
        if (entries[i].ei.image) {
            munmap(entries[i].ei.image, entries[i].ei.size);
        }
    }
    info->num_image_cache = 0;
}

HIDDEN int
elf_w (get_proc_name_with_info) (unw_addr_space_t as, pid_t pid, unw_word_t ip,
                                 char *buf, size_t buf_len, unw_word_t *offp, struct proc_info *info)
{
    unsigned long segbase, mapoff;
    int ret;
    char* file;

    struct mmap_cache_entry_t* entry = info->mmap_cache_search_void(info->tcp, ip);

    // mmap entry could not be null;
    assert(entry);

    file = entry->binary_filename;
    segbase = entry->start_addr;
    mapoff = entry->mmap_offset;



    // clear all cahces
//    if (info->update) {
//        struct image_cache_entry_t *entries = info->image_cache;
//        for (int i = 0; i < info->num_image_cache; i++) {
//            entries[i].need_update = true;
//        }
//        info->update = false;
//    }

    // search for cache
    ret = elf_w (get_proc_name_in_cache) (as, pid, file, segbase, mapoff, ip, buf, buf_len, offp, info);


    return ret;
}

HIDDEN int
elf_w (get_proc_name) (unw_addr_space_t as, pid_t pid, unw_word_t ip,
                       char *buf, size_t buf_len, unw_word_t *offp)
{
  unsigned long segbase, mapoff;
  struct elf_image ei;
  int ret;
  char file[PATH_MAX];


  ret = tdep_get_elf_image (&ei, pid, ip, &segbase, &mapoff, file, PATH_MAX);

  if (ret < 0)
    return ret;

  ret = elf_w (load_debuglink) (file, &ei, 1);

  if (ret < 0)
    return ret;

  ret = elf_w (get_proc_name_in_image) (as, &ei, segbase, mapoff, ip, buf, buf_len, offp);

  munmap (ei.image, ei.size);
  ei.image = NULL;

  return ret;
}

HIDDEN Elf_W (Shdr)*
elf_w (find_section) (struct elf_image *ei, const char* secname)
{
  Elf_W (Ehdr) *ehdr = ei->image;
  Elf_W (Shdr) *shdr;
  char *strtab;
  int i;

  if (!elf_w (valid_object) (ei))
    return 0;

  shdr = elf_w (section_table) (ei);
  if (!shdr)
    return 0;

  strtab = elf_w (string_table) (ei, ehdr->e_shstrndx);
  if (!strtab)
    return 0;

  for (i = 0; i < ehdr->e_shnum; ++i)
    {
      if (strcmp (strtab + shdr->sh_name, secname) == 0)
        {
          if (shdr->sh_offset + shdr->sh_size > ei->size)
            {
              Debug (1, "section \"%s\" outside image? (0x%lu > 0x%lu)\n",
                     secname,
                     (unsigned long) shdr->sh_offset + shdr->sh_size,
                     (unsigned long) ei->size);
              return 0;
            }

          Debug (16, "found section \"%s\" at 0x%lx\n",
                 secname, (unsigned long) shdr->sh_offset);
          return shdr;
        }

      shdr = (Elf_W (Shdr) *) (((char *) shdr) + ehdr->e_shentsize);
    }

  /* section not found */
  return 0;
}


/* Load a debug section, following .gnu_debuglink if appropriate
 * Loads ei from file if not already mapped.
 * If is_local, will also search sys directories /usr/local/dbg
 *
 * Returns 0 on success, failure otherwise.
 * ei will be mapped to file or the located .gnu_debuglink from file
 */
HIDDEN int
elf_w (load_debuglink) (const char* file, struct elf_image *ei, int is_local)
{
  int ret;
  Elf_W (Shdr) *shdr;
  Elf_W (Ehdr) *prev_image;
  off_t prev_size;

  if (!ei->image)
    {
      ret = elf_map_image(ei, file);
      if (ret)
	return ret;
    }

  prev_image = ei->image;
  prev_size = ei->size;

  /* Ignore separate debug files which contain a .gnu_debuglink section. */
  if (is_local == -1) {
    return 0;
  }

  shdr = elf_w (find_section) (ei, ".gnu_debuglink");
  if (shdr) {
    if (shdr->sh_size >= PATH_MAX ||
	(shdr->sh_offset + shdr->sh_size > ei->size))
      {
	return 0;
      }

    {
      char linkbuf[shdr->sh_size];
      char *link = ((char *) ei->image) + shdr->sh_offset;
      char *p;
      static const char *debugdir = "/usr/lib/debug";
      char basedir[strlen(file) + 1];
      char newname[shdr->sh_size + strlen (debugdir) + strlen (file) + 9];

      memcpy(linkbuf, link, shdr->sh_size);

      if (memchr (linkbuf, 0, shdr->sh_size) == NULL)
	return 0;

      ei->image = NULL;

      Debug(1, "Found debuglink section, following %s\n", linkbuf);

      p = strrchr (file, '/');
      if (p != NULL)
	{
	  memcpy (basedir, file, p - file);
	  basedir[p - file] = '\0';
	}
      else
	basedir[0] = 0;

      strcpy (newname, basedir);
      strcat (newname, "/");
      strcat (newname, linkbuf);
      ret = elf_w (load_debuglink) (newname, ei, -1);

      if (ret == -1)
	{
	  strcpy (newname, basedir);
	  strcat (newname, "/.debug/");
	  strcat (newname, linkbuf);
	  ret = elf_w (load_debuglink) (newname, ei, -1);
	}

      if (ret == -1 && is_local == 1)
	{
	  strcpy (newname, debugdir);
	  strcat (newname, basedir);
	  strcat (newname, "/");
	  strcat (newname, linkbuf);
	  ret = elf_w (load_debuglink) (newname, ei, -1);
	}

      if (ret == -1 || ret == 2)
        {
          /* No debuglink file found even though .gnu_debuglink existed */
          ei->image = prev_image;
          ei->size = prev_size;

          return 0;
        }
      else
        {
//          fprintf(stderr, "umap: 0x%lx, file= %s, newname = %s\n", (void*)prev_image, file, newname);
          munmap (prev_image, prev_size);
        }

      return ret;
    }
  }

  return 0;
}
