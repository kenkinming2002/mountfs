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
#include <sys/resource.h>

#include <assert.h>
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

static int mount_compar(const void *a, const void *b)
{
  const struct mount *mnt1 = a;
  const struct mount *mnt2 = b;
  return strlen(mnt1->target) - strlen(mnt2->target);
}

/// Compute the relative path of child from parent. The returned path always
/// consist of a leading directory separator even if parent == child.
///
/// For example:
///   path_relative("/", "/")  => "/"
///   path_relative("/", "/a")  => "/a"
///   path_relative("/a", "/a")  => "/"
///   path_relative("/a/b", "/a")  => "/b"
///   path_relative("/a/b/c", "/a")  => "/b/c"
///   path_relative("/aa/b/c", "/a") => NULL
///
/// This can be used detect if a path is under a mountpoint.
static const char *path_resolve_relative(const char *parent, const char *child)
{
  size_t n = strcmp(parent, "/") != 0 ? strlen(parent) : 0;
  if(strncmp(parent, child, n) != 0)
    return NULL;

  switch(child[n])
  {
  case '\0':
    return "/";
  case '/':
    return &child[n];
  default:
    return NULL;
  }
}

/// Similar to path_relative, but child must be a immediate child of parent. The
/// returned string is guaranteed to consist of no directory separator.
///
/// For example:
///   path_relative_component("/", "/")  => NULL
///   path_relative_component("/", "/a")  => "a"
///   path_relative_component("/a", "/a")  => NULL
///   path_relative_component("/a/b", "/a")  => "b"
///   path_relative_component("/a/b/c", "/a")  => NULL
///   path_relative_component("/aa/b/c", "/a") => NULL
///
/// This can be used detect if child is inside parent directory.
static const char *path_resolve_relative_component(const char *parent, const char *child)
{
  size_t n = strcmp(parent, "/") != 0 ? strlen(parent) : 0;
  if(strncmp(parent, child, n) != 0)
    return NULL;

  switch(child[n])
  {
  case '\0':
    return NULL;
  case '/':
    if(child[n+1] == '\0')
      return NULL;

    if(strchr(&child[n+1], '/'))
      return NULL;

    return &child[n+1];
  default:
    return NULL;
  }
}

static const char *path_resolve(const char *path, char buffer[PATH_MAX+1])
{
  // We loop in reverse because mounts are sorted by target length in ascending
  // order, and we only cares about the longest match
  for(size_t i=options.mounts.count-1; i<options.mounts.count; ++i)
  {
    struct mount *mount = &options.mounts.items[i];
    const char *rest = path_resolve_relative(mount->target, path);
    if(!rest)
      continue;

    if(snprintf(buffer, PATH_MAX+1, "%s%s", mount->source, rest) > PATH_MAX)
    {
      errno = ENAMETOOLONG;
      return NULL;
    }

    fprintf(stderr, "resolved path: %s -> %s\n", path, buffer);
    return buffer;
  }

  fprintf(stderr, "resolved path %s -> %s\n", path, path);
  return path;
}

static bool path_may_synthesize(const char *path)
{
  for(size_t i=0; i<options.mounts.count; --i)
  {
    const struct mount *mount = &options.mounts.items[i];
    if(path_resolve_relative(path, mount->target))
      return true;
  }
  return false;
}

#define SYNTHETIC_FH (uint64_t)-1

#define resolve_and_call_ext(expr, path, action)            \
  do {                                                      \
    const char *saved_path = path;                          \
                                                            \
    char buffer[PATH_MAX+1];                                \
    if(!(path = path_resolve(path, buffer)))                \
      return -errno;                                        \
                                                            \
    int result = (expr);                                    \
    if(result != -1)                                        \
      return 0;                                             \
                                                            \
    if(errno == ENOENT && path_may_synthesize(saved_path))  \
      action;                                               \
                                                            \
    return -errno;                                          \
  } while(0)

#define resolve_and_call2_ext(expr, path1, path2, action)       \
  do {                                                      \
    const char *saved_path1 = path1;                        \
    const char *saved_path2 = path2;                        \
                                                            \
    char buffer1[PATH_MAX+1];                               \
    if(!(path1 = path_resolve(path1, buffer1)))             \
      return -errno;                                        \
                                                            \
    char buffer2[PATH_MAX+1];                               \
    if(!(path2 = path_resolve(path2, buffer2)))             \
      return -errno;                                        \
                                                            \
    int result = (expr);                                    \
    if(result != -1)                                        \
      return 0;                                             \
                                                            \
    if(errno == ENOENT && path_may_synthesize(saved_path1)) \
      action;                                               \
                                                            \
    return -errno;                                          \
  } while(0)

#define resolve_and_call(expr, path) resolve_and_call_ext(expr, path, return -ENOTSUP)
#define resolve_and_call2(expr, path1, path2) resolve_and_call2_ext(expr, path1, path2, return -ENOTSUP)

#define resolve_and_call_protected(expr, path) \
  do {                                         \
    if(path_may_synthesize(path))              \
      return -ENOTSUP;                         \
                                               \
    char buffer[PATH_MAX+1];                   \
    if(!(path = path_resolve(path, buffer)))   \
      return -errno;                           \
                                               \
    int result = (expr);                       \
    if(result != -1)                           \
      return 0;                                \
                                               \
    return -errno;                             \
  } while(0)

#define resolve_and_call2_protected(expr, path1, path2)     \
  do {                                                      \
    if(path_may_synthesize(path1))                          \
      return -ENOTSUP;                                      \
                                                            \
    if(path_may_synthesize(path2))                          \
      return -ENOTSUP;                                      \
                                                            \
    char buffer1[PATH_MAX+1];                               \
    if(!(path1 = path_resolve(path1, buffer1)))             \
      return -errno;                                        \
                                                            \
    char buffer2[PATH_MAX+1];                               \
    if(!(path2 = path_resolve(path2, buffer2)))             \
      return -errno;                                        \
                                                            \
    int result = (expr);                                    \
    if(result != -1)                                        \
      return 0;                                             \
                                                            \
    return -errno;                                          \
  } while(0)

///////////////////////
/// Init or destroy ///
///////////////////////

static void *mountfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
  (void)conn;
  (void)cfg;
  return NULL;
}

///////////////////////////////
/// Open or release handles ///
///////////////////////////////

static int mountfs_open(const char *path, struct fuse_file_info *fi)
{
  if(path_may_synthesize(path))
    return -EEXIST;

  char buffer[PATH_MAX+1];
  if(!(path = path_resolve(path, buffer)))
    return -errno;

  int fd = open(path, fi->flags);
  if(fd == -1)
    return -errno;

  fi->fh = fd;
  return 0;
}

static int mountfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
  if(path_may_synthesize(path))
    return -EEXIST;

  char buffer[PATH_MAX+1];
  if(!(path = path_resolve(path, buffer)))
    return -errno;

  int fd = open(path, fi->flags, mode);
  if(fd == -1)
    return -errno;

  fi->fh = fd;
  return 0;
}

static int mountfs_opendir(const char *path, struct fuse_file_info *fi)
{
  char buffer[PATH_MAX+1];
  const char *resolved_path = path_resolve(path, buffer);
  if(!resolved_path)
    return -errno;

  int fd = open(resolved_path, fi->flags | O_DIRECTORY);
  if(fd != -1)
  {
    fi->fh = fd;
    return 0;
  }

  if(errno == ENOENT && path_may_synthesize(path))
  {
    fi->fh = SYNTHETIC_FH;
    return 0;
  }

  return -errno;
}

static int mountfs_release(const char *path, struct fuse_file_info *fi)
{
  return close(fi->fh) != -1 ? 0 : -errno;
}

static int mountfs_releasedir(const char *path, struct fuse_file_info *fi)
{
  if(fi->fh == SYNTHETIC_FH)
    return 0;

  return close(fi->fh) != -1 ? 0 : -errno;
}

/////////////////////////////////////
/// Acts on paths or file handles ///
/////////////////////////////////////

static int mountfs_getattr(const char *path, struct stat *statbuf, struct fuse_file_info *fi)
{
  if(!fi)
    resolve_and_call_ext(lstat(path, statbuf), path, {
        memset(statbuf, 0, sizeof *statbuf);

        statbuf->st_mode = S_IFDIR | S_IRWXU;
        statbuf->st_nlink = 1;
        statbuf->st_uid = getuid();
        statbuf->st_gid = getgid();
        statbuf->st_size = 0;
        statbuf->st_blksize = 1024;
        statbuf->st_blocks = 0;

        struct timespec timespec;
        if(clock_gettime(CLOCK_REALTIME, &timespec) == -1)
          return -errno;

        statbuf->st_atim = timespec;
        statbuf->st_mtim = timespec;
        statbuf->st_ctim = timespec;

        return 0;
    });
  else
    return fstat(fi->fh, statbuf) != -1 ? 0 : -errno;

}

static int mountfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
{
  if(!fi)
    resolve_and_call(lchmod(path, mode), path);
  else
    return fchmod(fi->fh, mode) != -1 ? 0 : -errno;
}

static int mountfs_chown(const char *path, uid_t owner, gid_t group, struct fuse_file_info *fi)
{
  if(!fi)
    resolve_and_call(lchown(path, owner, group), path);
  else
    return fchown(fi->fh, owner, group) != -1 ? 0 : -errno;
}

static int mountfs_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi)
{
  if(!fi)
    resolve_and_call(utimensat(AT_FDCWD, path, tv, AT_SYMLINK_NOFOLLOW), path);
  else
    return futimens(fi->fh, tv) != -1 ? 0 : -errno;
}

static int mountfs_truncate(const char *path, off_t length, struct fuse_file_info *fi)
{
  if(!fi)
    resolve_and_call(truncate(path, length), path);
  else
    return ftruncate(fi->fh, length) != -1 ? 0 : -errno;
}

//////////////////////////
/// Acts on paths only ///
//////////////////////////

static int mountfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
  resolve_and_call(lsetxattr(path, name, value, size, flags), path);
}

static int mountfs_getxattr(const char *path, const char *name, char *value, size_t size)
{
  resolve_and_call(lgetxattr(path, name, value, size), path);
}

static int mountfs_listxattr(const char *path, char *list, size_t size)
{
  resolve_and_call(llistxattr(path, list, size), path);
}

static int mountfs_removexattr(const char *path, const char *name)
{
  resolve_and_call(lremovexattr(path, name), path);
}

static int mountfs_link(const char *oldpath, const char *newpath)
{
  resolve_and_call2(link(oldpath, newpath), oldpath, newpath);
}

static int readlink_wrapper(const char *path, char *buf, size_t count)
{
  ssize_t n = readlink(path, buf, count-1);
  if(n == -1)
    return -1;

  buf[n] = '\0';
  return 0;
}

static int mountfs_readlink(const char *path, char *buf, size_t count)
{
  resolve_and_call(readlink_wrapper(path, buf, count), path);
}

static int mountfs_symlink(const char *target, const char *linkpath)
{
  resolve_and_call(symlink(target, linkpath), linkpath);
}

static int mountfs_unlink(const char *path)
{
  resolve_and_call_protected(unlink(path), path);
}

static int mountfs_rename(const char *oldpath, const char *newpath, unsigned int flags)
{
  resolve_and_call2_protected(renameat2(AT_FDCWD, oldpath, AT_FDCWD, newpath, flags), oldpath, newpath);
}

static int mountfs_mknod(const char *path, mode_t mode, dev_t dev)
{
  resolve_and_call_protected(S_ISFIFO(mode) ? mkfifo(path, mode) : mknod(path, mode, dev), path);
}

static int mountfs_mkdir(const char *path, mode_t mode)
{
  resolve_and_call_protected(mkdir(path, mode), path);
}

static int mountfs_rmdir(const char *path)
{
  resolve_and_call_protected(rmdir(path), path);
}

/////////////////////////////////
/// Acts on file handles only ///
/////////////////////////////////

static ssize_t mountfs_copy_file_range(const char *path_in, struct fuse_file_info *fi_in, off_t offset_in, const char *path_out, struct fuse_file_info *fi_out, off_t offset_out, size_t size, int flags)
{
  ssize_t result = copy_file_range(fi_in->fh, &offset_in, fi_out->fh, &offset_out, size, flags);
  return result != -1 ? result : -errno;
}

static int mountfs_fallocate(const char *path, int mode, off_t offset, off_t length, struct fuse_file_info *fi)
{
  return fallocate(fi->fh, mode, offset, length) != -1 ? 0 : -errno;
}

static int mountfs_flock(const char *path, struct fuse_file_info *fi, int op)
{
  return flock(fi->fh, op) != -1 ? 0 : -errno;
}

static int mountfs_flush(const char *path, struct fuse_file_info *fi)
{
  return close(dup(fi->fh)) != -1 ? 0 : -errno;
}

static int mountfs_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
  if(datasync)
    return fdatasync(fi->fh) != -1 ? 0 : -errno;
  else
    return fsync(fi->fh) != -1 ? 0 : -errno;
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

static int mountfs_write(const char *path, const char *buf, size_t count, off_t offset, struct fuse_file_info *fi)
{
  ssize_t result = pwrite(fi->fh, buf, count, offset);
  return result != -1 ? result : -errno;
}

static int mountfs_write_buf(const char *path, struct fuse_bufvec *buf, off_t offset, struct fuse_file_info *fi)
{
  struct fuse_bufvec dst = FUSE_BUFVEC_INIT(fuse_buf_size(buf));
  dst.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
  dst.buf[0].fd = fi->fh;
  dst.buf[0].pos = offset;
  return fuse_buf_copy(&dst, buf, FUSE_BUF_SPLICE_NONBLOCK);
}

//////////////////////////////////////
/// Acts on directory handles only ///
//////////////////////////////////////

static int mountfs_readdir(const char *path, void *buf, fuse_fill_dir_t fill_dir, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
  if(fi->fh != SYNTHETIC_FH)
  {
    DIR *dirp = fdopendir(fi->fh);
    if(!dirp)
      return -errno;

    errno = 0;

    struct dirent *dirent;
    while((dirent = readdir(dirp)))
      fill_dir(buf, dirent->d_name, NULL, 0, 0);

    if(errno != 0)
      return -errno;
  }

  for(size_t i=0; i<options.mounts.count; ++i)
  {
    struct mount *mount = &options.mounts.items[i];
    const char *name = path_resolve_relative_component(path, mount->target);
    if(name)
      fill_dir(buf, name, NULL, 0, 0);
  }

  return 0;
}

static int mountfs_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
  if(datasync)
    return fdatasync(fi->fh) != -1 ? 0 : -errno;
  else
    return fsync(fi->fh) != -1 ? 0 : -errno;
}

static struct fuse_operations mountfs_fops = {
  // Init or destroy
  .init = mountfs_init,
  .destroy = NULL,

  // Open and release handles
  .open = mountfs_open,
  .opendir = mountfs_opendir,
  .release = mountfs_release,
  .releasedir = mountfs_releasedir,

  // Acts on paths or file handles
  .getattr = mountfs_getattr,
  .chmod = mountfs_chmod,
  .chown = mountfs_chown,
  .utimens = mountfs_utimens,
  .truncate = mountfs_truncate,

  // Acts on paths only
  .setxattr = mountfs_setxattr,
  .getxattr = mountfs_getxattr,
  .listxattr = mountfs_listxattr,
  .removexattr = mountfs_removexattr,
  .link = mountfs_link,
  .unlink = mountfs_unlink,
  .rename = mountfs_rename,
  .readlink = mountfs_readlink,
  .symlink = mountfs_symlink,
  .create = mountfs_create,
  .mknod = mountfs_mknod,
  .mkdir = mountfs_mkdir,
  .rmdir = mountfs_rmdir,

  // Acts on file handles only
  .copy_file_range = mountfs_copy_file_range,
  .fallocate = mountfs_fallocate,
  .flock = mountfs_flock,
  .flush = mountfs_flush,
  .fsync = mountfs_fsync,
  .lseek = mountfs_lseek,
  .read = mountfs_read,
  .read_buf = mountfs_read_buf,
  .write = mountfs_write,
  .write_buf = mountfs_write_buf,

  // Acts on directory handles only
  .readdir = mountfs_readdir,
  .fsyncdir = mountfs_fsyncdir,

  // Unimplemented
  .poll = NULL,
  .ioctl = NULL,
  .lock = NULL,
};

static void raise_rlimit(void)
{
  struct rlimit rlimit;
  if(getrlimit(RLIMIT_NOFILE, &rlimit) == -1)
  {
    fprintf(stderr, "warning: failed to get rlimit for number of opened file descriptor\n");
    return;
  }

  rlim_t old = rlimit.rlim_cur;
  rlimit.rlim_cur = rlimit.rlim_max;

  if(setrlimit(RLIMIT_NOFILE, &rlimit) == -1)
  {
    fprintf(stderr, "warning: failed to raise rlimit for number of opened file descriptor\n");
    return;
  }

  fprintf(stderr, "raised rlimit for number of opened file descriptor from %jd to %jd\n", old, rlimit.rlim_cur);
}

static void setup(void)
{
  qsort(options.mounts.items, options.mounts.count, sizeof options.mounts.items[0], mount_compar);
  raise_rlimit();
}

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

  setup();

  fuse_opt_add_arg(&args, "-o");
  fuse_opt_add_arg(&args, "default_permissions");

  int result = fuse_main(args.argc, args.argv, &mountfs_fops, NULL);
  fuse_opt_free_args(&args);
  return result;
}

