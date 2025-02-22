#define _GNU_SOURCE

#define FUSE_USE_VERSION 31
#include <fuse.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <sys/ioctl.h>
#include <sys/file.h>

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

static void help(const char *program_name)
{
  fprintf(stderr, "usage: %s [options] mountpoint\n\n", program_name);
  fprintf(stderr, "File-system specific options:\n");
  fprintf(stderr, "    -m, --mount=target:source    Add a new pseudo mount\n");
  fprintf(stderr, "\n");
}

struct mount
{
  const char *target;
  const char *source;
};

struct mounts
{
  struct mount *items;
  size_t count;
  size_t capacity;
};

struct mountfs_options
{
  struct mounts mounts;
  bool help;
};

static struct mountfs_options options = {0};

enum option_key
{
  OPTION_KEY_HELP,
  OPTION_KEY_MOUNT,
};

static struct fuse_opt option_specs[] = {
  FUSE_OPT_KEY("-h", OPTION_KEY_HELP),
  FUSE_OPT_KEY("--help", OPTION_KEY_HELP),
  FUSE_OPT_KEY("-m %s", OPTION_KEY_MOUNT),
  FUSE_OPT_KEY("--mount=%s", OPTION_KEY_MOUNT),
  FUSE_OPT_END,
};

static const char *strip(const char *s, const char *prefix)
{
  size_t n = strlen(prefix);
  return strncmp(s, prefix, n) == 0 ? s + n : NULL;
}

static int process_option(void *data, const char *arg, int key, struct fuse_args *outargs)
{
  struct mountfs_options *options = data;
  switch(key)
  {
  case OPTION_KEY_MOUNT:
    {
      const char *s = NULL;
      if(!s) s = strip(arg, "-m");
      if(!s) s = strip(arg, "--mount=");
      if(!s) abort();

      char *p = strchr(s, ':');
      if(!p)
      {
        fprintf(stderr, "error: invalid format for mount(got %s)\n", s);
        return 1;
      }
      *p = '\0';

      if(options->mounts.capacity == options->mounts.count)
      {
        options->mounts.capacity = options->mounts.count != 0 ? options->mounts.count * 2 : 1;
        options->mounts.items = realloc(options->mounts.items, options->mounts.capacity * sizeof options->mounts.items[0]);
      }

      struct mount mount;
      mount.target = strdup(s);
      mount.source = strdup(p+1);
      options->mounts.items[options->mounts.count++] = mount;
    }
    return 0;
  case OPTION_KEY_HELP:
    options->help = true;
  default:
    return 1;
  }
}

static char *resolve_path(const char *path)
{
  // If this resolve back to ourself, we are doomed

  for(size_t i=0; i<options.mounts.count; ++i)
  {
    struct mount *mount = &options.mounts.items[i];

    size_t n = strlen(mount->target);
    if(strncmp(path, mount->target, n) != 0)
      continue;

    char *new_path;
    if(asprintf(&new_path, "%s%s", mount->source, path + n) == -1)
    {
      errno = ENOMEM;
      return NULL;
    }
    fprintf(stderr, "resolved path %s -> %s\n", path, new_path);
    return new_path;
  }
  fprintf(stderr, "resolved path %s -> %s\n", path, path);
  return strdup(path);
}

static void *mountfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
  (void)conn;
  (void)cfg;
  return NULL;
}

static int mountfs_do_open(const char *path, struct fuse_file_info *fi)
{
  char *new_path = resolve_path(path);
  if(!new_path)
    goto err;

  int fd = open(new_path, fi->flags);
  if(fd == -1)
    goto err_free_path;

  free(new_path);
  fi->fh = fd;
  return 0;

err_free_path:
  free(new_path);
err:
  return -errno;
}

static int mountfs_open(const char *path, struct fuse_file_info *fi)
{
  char *new_path = resolve_path(path);
  if(!new_path)
    return -errno;

  int fd = open(new_path, fi->flags);
  free(new_path);
  if(fd != -1)
  {
    fi->fh = fd;
    return 0;
  }
  else
    return -errno;
}

static int mountfs_opendir(const char *path, struct fuse_file_info *fi)
{
  char *new_path = resolve_path(path);
  if(!new_path)
    return -errno;

  int fd = open(new_path, fi->flags | O_DIRECTORY);
  free(new_path);
  if(fd != -1)
  {
    fi->fh = fd;
    return 0;
  }
  else
    return -errno;
}

static int mountfs_do_release(const char *path, struct fuse_file_info *fi)
{
  return close(fi->fh) != -1 ? 0 : -errno;
}

static int mountfs_getattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi)
{
  if(!fi)
  {
    char *new_path = resolve_path(path);
    if(!new_path)
      return -errno;

    int result = lstat(new_path, statbuf);
    free(new_path);
    return result != -1 ? 0 : -errno;
  }
  else
    return fstat(fi->fh, statbuf) != -1 ? 0 : -errno;

}

static int mountfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
{
  if(!fi)
  {
    char *new_path = resolve_path(path);
    if(!new_path)
      return -errno;

    int result = lchmod(new_path, mode);
    free(new_path);
    return result != -1 ? 0 : -errno;
  }
  else
    return fchmod(fi->fh, mode) != -1 ? 0 : -errno;
}

static int mountfs_chown(const char *path, uid_t owner, gid_t group, struct fuse_file_info *fi)
{
  if(!fi)
  {
    char *new_path = resolve_path(path);
    if(!new_path)
      return -errno;

    int result = lchown(new_path, owner, group);
    free(new_path);
    return result != -1 ? 0 : -errno;
  }
  else
    return fchown(fi->fh, owner, group) != -1 ? 0 : -errno;
}

static int mountfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
  char *new_path = resolve_path(path);
  if(!new_path)
    return -errno;

  int result = lsetxattr(new_path, name, value, size, flags);
  free(new_path);
  return result != -1 ? 0 : -errno;
}

static int mountfs_getxattr(const char *path, const char *name, char *value, size_t size)
{
  char *new_path = resolve_path(path);
  if(!new_path)
    return -errno;

  int result = lgetxattr(new_path, name, value, size);
  free(new_path);
  return result != -1 ? 0 : -errno;
}

static int mountfs_listxattr(const char *path, char *list, size_t size)
{
  char *new_path = resolve_path(path);
  if(!new_path)
    return -errno;

  int result = llistxattr(new_path, list, size);
  free(new_path);
  return result != -1 ? 0 : -errno;
}

static int mountfs_removexattr(const char *path, const char *name)
{
  char *new_path = resolve_path(path);
  if(!new_path)
    return -errno;

  int result = lremovexattr(new_path, name);
  free(new_path);
  return result != -1 ? 0 : -errno;
}

static int mountfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
  char *new_path = resolve_path(path);
  if(!new_path)
    return -errno;

  int fd = open(path, fi->flags, mode);
  free(new_path);
  if(fd != -1)
  {
    fi->fh = fd;
    return 0;
  }
  else
    return -errno;
}

static int mountfs_mknod(const char *path, mode_t mode, dev_t dev)
{
  char *new_path = resolve_path(path);
  if(!new_path)
    return -errno;

  int result = S_ISFIFO(mode) ? mkfifo(new_path, mode) : mknod(new_path, mode, dev);
  free(new_path);
  return result;
}

static int mountfs_mkdir(const char *path, mode_t mode)
{
  char *new_path = resolve_path(path);
  if(!new_path)
    return -errno;

  int result = mkdir(new_path, mode);
  free(new_path);
  return result;
}

static int mountfs_rmdir(const char *path)
{
  char *new_path = resolve_path(path);
  if(!new_path)
    return -errno;

  int result = rmdir(new_path);
  free(new_path);
  return result;
}

static int mountfs_truncate(const char *path, off_t length, struct fuse_file_info *fi)
{
  if(!fi)
  {
    char *new_path = resolve_path(path);
    if(!new_path)
      return -errno;

    int result = truncate(new_path, length);
    free(new_path);
    return result != -1 ? 0 : -errno;
  }
  else
    return ftruncate(fi->fh, length) != -1 ? 0 : -errno;
}

static int mountfs_fallocate(const char *path, int mode, off_t offset, off_t length, struct fuse_file_info *fi)
{
  return fallocate(fi->fh, mode, offset, length) != -1 ? 0 : -errno;
}

static int mountfs_link(const char *oldpath, const char *newpath)
{
  char *new_oldpath = resolve_path(oldpath);
  if(!new_oldpath)
    return -errno;

  char *new_newpath = resolve_path(newpath);
  if(!new_newpath)
  {
    free(new_oldpath);
    return -errno;
  }

  int result = link(new_oldpath, new_newpath);
  free(new_oldpath);
  free(new_newpath);
  return result;
}

static int mountfs_unlink(const char *path)
{
  char *new_path = resolve_path(path);
  if(!new_path)
    return -errno;

  int result = unlink(new_path);
  free(new_path);
  return result;
}

static int mountfs_rename(const char *oldpath, const char *newpath, unsigned int flags)
{
  char *new_oldpath = resolve_path(oldpath);
  if(!new_oldpath)
    return -errno;

  char *new_newpath = resolve_path(newpath);
  if(!new_newpath)
  {
    free(new_oldpath);
    return -errno;
  }

  int result = renameat2(AT_FDCWD, new_oldpath, AT_FDCWD, new_newpath, flags);
  free(new_oldpath);
  free(new_newpath);
  return result;
}

static int mountfs_symlink(const char *target, const char *linkpath)
{
  char *new_linkpath = resolve_path(linkpath);
  if(!new_linkpath)
    return -errno;

  int result = symlink(target, linkpath);
  free(new_linkpath);
  return result;
}

static int mountfs_readlink(const char *path, char *buf, size_t count)
{
  char *new_path = resolve_path(path);
  if(!new_path)
    return -errno;

  int result = readlink(new_path, buf, count);
  free(new_path);
  return result != -1 ? 0 : -errno;
}

static off_t mountfs_lseek(const char *path, off_t off, int whence, struct fuse_file_info *fi)
{
  off_t result = lseek(fi->fh, off, whence);
  return result != -1 ? result : -errno;
}

static int mountfs_read(const char *path, char *buf, size_t count, off_t offset, struct fuse_file_info *fi)
{
  ssize_t result = pread(fi->fh, buf, count, offset);
  return result != -1 ? result : -errno;
}

static int mountfs_write(const char *path, const char *buf, size_t count, off_t offset, struct fuse_file_info *fi)
{
  ssize_t result = pwrite(fi->fh, buf, count, offset);
  return result != -1 ? result : -errno;
}

static int mountfs_read_buf(const char *path, struct fuse_bufvec **bufp, size_t size, off_t offset, struct fuse_file_info *fi)
{
  *bufp = malloc(sizeof(**bufp));
  if(!*bufp)
    return -ENOMEM;

  **bufp = FUSE_BUFVEC_INIT(size);
  (*bufp)->buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
  (*bufp)->buf[0].fd = fi->fh;
  (*bufp)->buf[0].pos = offset;
  return 0;
}

static int mountfs_write_buf(const char *path, struct fuse_bufvec *buf, off_t offset, struct fuse_file_info *fi)
{
  struct fuse_bufvec dst = FUSE_BUFVEC_INIT(fuse_buf_size(buf));
  dst.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
  dst.buf[0].fd = fi->fh;
  dst.buf[0].pos = offset;
  return fuse_buf_copy(&dst, buf, FUSE_BUF_SPLICE_NONBLOCK);
}

static ssize_t mountfs_copy_file_range(const char *path_in, struct fuse_file_info *fi_in, off_t offset_in, const char *path_out, struct fuse_file_info *fi_out, off_t offset_out, size_t size, int flags)
{
  ssize_t result = copy_file_range(fi_in->fh, &offset_in, fi_out->fh, &offset_out, size, flags);
  return result != -1 ? result : -errno;
}

static int mountfs_readdir(const char *path, void *buf, fuse_fill_dir_t fill_dir, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
  int fd = fi->fh;

  char buffer[1024];
  long n;
  while((n = syscall(SYS_getdents, fd, buffer, sizeof buffer)) > 0)
  {
    struct linux_dirent
    {
      unsigned long  d_ino;
      off_t          d_off;
      unsigned short d_reclen;
      char           d_name[];
    };

    for(struct linux_dirent *
        dirent = (struct linux_dirent *)buffer;
        dirent < (struct linux_dirent *)(buffer + n);
        dirent = (struct linux_dirent *)((char *)dirent + dirent->d_reclen))
      fill_dir(buf, dirent->d_name, NULL, 0, 0);
  }
  return n != -1 ? 0 : -errno;
}

static int mountfs_flush(const char *path, struct fuse_file_info *fi)
{
  return close(dup(fi->fh)) != -1 ? 0 : -errno;
}

static int mountfs_do_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
  if(datasync)
    return fdatasync(fi->fh) != -1 ? 0 : -errno;
  else
    return fsync(fi->fh) != -1 ? 0 : -errno;
}

static int mountfs_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi)
{
  if(!fi)
  {
    char *new_path = resolve_path(path);
    if(!new_path)
      return -errno;

    int result = utimensat(AT_FDCWD, new_path, tv, AT_SYMLINK_NOFOLLOW);
    free(new_path);
    return result != -1 ? 0 : -errno;
  }
  else
    return futimens(fi->fh, tv) != -1 ? 0 : -errno;
}

static int mountfs_flock(const char *path, struct fuse_file_info *fi, int op)
{
  return flock(fi->fh, op) != -1 ? 0 : -errno;
}

static struct fuse_operations mountfs_fops = {
    .init = mountfs_init,
    .destroy = NULL,

    // Open
    .open = mountfs_open,
    .opendir = mountfs_opendir,

    // Release
    .release = mountfs_do_release,
    .releasedir = mountfs_do_release,

    // Attributes
    .getattr = mountfs_getattr,
    .chmod = mountfs_chmod,
    .chown = mountfs_chown,

    // Extended attributes
    .setxattr = mountfs_setxattr,
    .getxattr = mountfs_getxattr,
    .listxattr = mountfs_listxattr,
    .removexattr = mountfs_removexattr,

    // Things
    .create = mountfs_create,
    .mknod = mountfs_mknod,
    .mkdir = mountfs_mkdir,
    .rmdir = mountfs_rmdir,

    // Allocation of files
    .truncate = mountfs_truncate,
    .fallocate = mountfs_fallocate,

    // File link
    .link = mountfs_link,
    .unlink = mountfs_unlink,
    .rename = mountfs_rename,
    .symlink = mountfs_symlink,
    .readlink = mountfs_readlink,

    // File Seek/read/write
    .lseek = mountfs_lseek,
    .read = mountfs_read,
    .write = mountfs_write,
    .read_buf = mountfs_read_buf,
    .write_buf = mountfs_write_buf,

    // Misc file operations
    .copy_file_range = mountfs_copy_file_range,

    // Poll
    .poll = NULL,

    // Directory creation/removal/reading
    .readdir = mountfs_readdir,

    // Sync
    .flush = mountfs_flush,
    .fsync = mountfs_do_fsync,
    .fsyncdir = mountfs_do_fsync,

    // Misc
    .utimens = mountfs_utimens,
    .ioctl = NULL,

    // Locking
    .lock = NULL,
    .flock = mountfs_flock,
};

int main(int argc, char *argv[])
{
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  if(fuse_opt_parse(&args, &options, option_specs, process_option) == -1)
    return EXIT_FAILURE;

  if(options.help)
  {
    help(argv[0]);
    argv[0][0] = '\0';
  }

  int result = fuse_main(args.argc, args.argv, &mountfs_fops, NULL);
  fuse_opt_free_args(&args);
  return result;
}
