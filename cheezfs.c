#define _GNU_SOURCE
#define FUSE_USE_VERSION 312
#include <fuse_lowlevel.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/file.h>
#include <sys/xattr.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <jansson.h>

#include "tree.h"

enum {
	CHEEZ_INIT,
	CHEEZ_PREPARE,
	CHEEZ_BULK,
	CHEEZ_IGNORE,
};

struct czfs_inode {
	int fd;
	ino_t ino;
	dev_t dev;
	uint64_t refcount;
	RB_ENTRY(czfs_inode) link;
};

static int
inode_compare(struct czfs_inode *a, struct czfs_inode *b)
{
	if (a->ino != b->ino)
		return (int64_t)a->ino - (int64_t)b->ino;
	if (a->dev != b->dev)
		return (int64_t)a->dev - (int64_t)b->dev;
	return 0;
}

RB_HEAD(czfs_itree, czfs_inode);

struct czfs_data {
	char *source;
	pthread_mutex_t mutex;
	struct czfs_itree head;
	struct czfs_inode root;
};

static const struct fuse_opt czfs_opts[] = {
    {"--source=%s", offsetof(struct czfs_data, source), 1},
    FUSE_OPT_END,
};

RB_GENERATE(czfs_itree, czfs_inode, link, inode_compare);

struct czfs_tensor {
	char *key;
	int fd;
	size_t data_offsets[2];
	RB_ENTRY(czfs_tensor) link;
};

static int
tensor_compare(struct czfs_tensor *a, struct czfs_tensor *b)
{
	fprintf(stderr, "compare a=%s b=%s\n", a->key, b->key);
	return strcmp(a->key, b->key);
}

RB_HEAD(czfs_ttree, czfs_tensor);
RB_GENERATE(czfs_ttree, czfs_tensor, link, tensor_compare);

struct czfs_filep {
	int fd;
	int state;
	uint64_t n;
	struct czfs_ttree tensors;
};

static struct czfs_filep *
czfs_filep(struct fuse_file_info *fi)
{
	return (struct czfs_filep *)(uintptr_t)fi->fh;
}

static struct czfs_data *
czfs_data(fuse_req_t req)
{
	return (struct czfs_data *)fuse_req_userdata(req);
}

static struct czfs_inode *
czfs_inode(fuse_req_t req, fuse_ino_t ino)
{
	if (ino != FUSE_ROOT_ID)
		return (struct czfs_inode *)(uintptr_t)ino;
	return &czfs_data(req)->root;
}

static void
czfs_init(void *userdata, struct fuse_conn_info *conn)
{
	struct czfs_data *data = (struct czfs_data *)userdata;
	pthread_mutex_init(&data->mutex, NULL);
	RB_INIT(&data->head);
	data->root.fd = open(data->source, O_PATH | O_NOFOLLOW);
	if (data->root.fd < 0) {
		perror("open");
		exit(1);
	}
	data->root.refcount = 2;
}

static int
do_lookup(fuse_req_t req, fuse_ino_t parent, const char *name,
	  struct fuse_entry_param *e)
{
	int newfd;
	int res;
	int saverr;
	struct czfs_data *data = czfs_data(req);
	struct czfs_inode *inode = malloc(sizeof(struct czfs_inode));
	struct czfs_inode *ret;
	e->attr_timeout = 0;
	e->entry_timeout = 0;

	newfd = openat(czfs_inode(req, parent)->fd, name, O_PATH | O_NOFOLLOW);
	if (newfd == -1)
		goto out_err;

	res = fstatat(newfd, "", &e->attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		goto out_err;

	inode->fd = newfd;
	inode->ino = e->attr.st_ino;
	inode->dev = e->attr.st_dev;
	inode->refcount = 1;
	pthread_mutex_lock(&data->mutex);
	ret = RB_INSERT(czfs_itree, &data->head, inode);
	if (ret) {
		close(newfd);
		free(inode);
		inode = ret;
		inode->refcount++;
	}
	pthread_mutex_unlock(&data->mutex);
	e->ino = (uintptr_t)inode;
	return (0);

out_err:
	saverr = errno;
	if (newfd != -1)
		close(newfd);
	return (saverr);
}

static void
czfs_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode)
{
	struct fuse_entry_param e;
	struct czfs_inode *dir;
	int err;

	dir = czfs_inode(req, parent);

	err = mkdirat(dir->fd, name, mode);
	if (err) {
		fuse_reply_err(req, errno);
		return;
	}

	err = do_lookup(req, parent, name, &e);
	if (err == 0)
		fuse_reply_entry(req, &e);
	else
		fuse_reply_err(req, err);
}

static void
czfs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	int res;
	struct stat buf;
	int fd = fi ? czfs_filep(fi)->fd : czfs_inode(req, ino)->fd;

	res = fstatat(fd, "", &buf, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1) {
		fuse_reply_err(req, errno);
		return;
	}
	fuse_reply_attr(req, &buf, 1.0);
}

static void
czfs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int valid,
	     struct fuse_file_info *fi)
{
	int saverr;
	char procname[64];
	struct czfs_inode *inode = czfs_inode(req, ino);
	int ifd = inode->fd;
	int res;

	if (valid & FUSE_SET_ATTR_MODE) {
		if (fi) {
			res = fchmod(czfs_filep(fi)->fd, attr->st_mode);
		} else {
			sprintf(procname, "/proc/self/fd/%i", ifd);
			res = chmod(procname, attr->st_mode);
		}

		if (res == -1)
			goto out_err;
	}
	if (valid & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
		uid_t uid =
		    (valid & FUSE_SET_ATTR_UID) ? attr->st_uid : (uid_t)-1;
		gid_t gid =
		    (valid & FUSE_SET_ATTR_GID) ? attr->st_gid : (gid_t)-1;

		res = fchownat(ifd, "", uid, gid,
			       AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
		if (res == -1)
			goto out_err;
	}
	if (valid & FUSE_SET_ATTR_SIZE) {
		if (fi) {
			res = ftruncate(czfs_filep(fi)->fd, attr->st_size);
		} else {
			sprintf(procname, "/proc/self/fd/%i", ifd);
			res = truncate(procname, attr->st_size);
		}
		if (res == -1)
			goto out_err;
	}
	if (valid & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
		struct timespec tv[2];

		tv[0].tv_sec = 0;
		tv[1].tv_sec = 0;
		tv[0].tv_nsec = UTIME_OMIT;
		tv[1].tv_nsec = UTIME_OMIT;

		if (valid & FUSE_SET_ATTR_ATIME_NOW)
			tv[0].tv_nsec = UTIME_NOW;
		else if (valid & FUSE_SET_ATTR_ATIME)
			tv[0] = attr->st_atim;

		if (valid & FUSE_SET_ATTR_MTIME_NOW)
			tv[1].tv_nsec = UTIME_NOW;
		else if (valid & FUSE_SET_ATTR_MTIME)
			tv[1] = attr->st_mtim;

		if (fi)
			res = futimens(czfs_filep(fi)->fd, tv);
		else {
			sprintf(procname, "/proc/self/fd/%i", ifd);
			res = utimensat(AT_FDCWD, procname, tv, 0);
		}
		if (res == -1)
			goto out_err;
	}

	czfs_getattr(req, ino, fi);
	return;
out_err:
	saverr = errno;
	fuse_reply_err(req, saverr);
}

static void
czfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fuse_entry_param e;
	int err;

	err = do_lookup(req, parent, name, &e);
	if (err)
		fuse_reply_err(req, err);
	else
		fuse_reply_entry(req, &e);
}

struct czfs_dirp {
	DIR *dp;
	struct dirent *entry;
	off_t offset;
};

static struct czfs_dirp *
czfs_dirp(struct fuse_file_info *fi)
{
	return (struct czfs_dirp *)(uintptr_t)fi->fh;
}

static void
czfs_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	int error = ENOMEM;
	struct czfs_dirp *d = malloc(sizeof(struct czfs_dirp));
	int fd = -1;

	if (d == NULL)
		goto out;

	fd = openat(czfs_inode(req, ino)->fd, ".", O_RDONLY);
	if (fd == -1)
		goto out_errno;

	d->dp = fdopendir(fd);
	if (d->dp == NULL)
		goto out_errno;

	d->offset = 0;
	d->entry = NULL;
	fi->fh = (uintptr_t)d;
	fuse_reply_open(req, fi);
	return;
out_errno:
	error = errno;
out:
	if (d) {
		if (fd != -1)
			close(fd);
		free(d);
	}
	fuse_reply_err(req, error);
}

static int
is_dot_or_dotdot(const char *name)
{
	return name[0] == '.' &&
	       (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

static void
do_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
	   struct fuse_file_info *fi, int plus)
{
	struct czfs_dirp *d = czfs_dirp(fi);
	char *buf;
	char *p;
	size_t rem = size;
	int err = 0;

	buf = malloc(size);
	if (!buf) {
		err = ENOMEM;
		goto error;
	}
	p = buf;

	if (offset != d->offset) {
		seekdir(d->dp, offset);
		d->entry = NULL;
		d->offset = offset;
	}
	while (1) {
		size_t entsize;
		off_t nextoff;
		const char *name;

		if (!d->entry) {
			errno = 0;
			d->entry = readdir(d->dp);
			if (!d->entry) {
				if (errno) {
					err = errno;
					goto error;
				} else {
					break;
				}
			}
		}
		nextoff = d->entry->d_off;
		name = d->entry->d_name;
		if (plus) {
			struct fuse_entry_param e;
			if (is_dot_or_dotdot(name)) {
				e = (struct fuse_entry_param){
				    .attr.st_ino = d->entry->d_ino,
				    .attr.st_mode = d->entry->d_type << 12,
				};
			} else {
				err = do_lookup(req, ino, name, &e);
				if (err)
					goto error;
			}

			entsize = fuse_add_direntry_plus(req, p, rem, name, &e,
							 nextoff);
		} else {
			struct stat st = {
			    .st_ino = d->entry->d_ino,
			    .st_mode = d->entry->d_type << 12,
			};
			entsize =
			    fuse_add_direntry(req, p, rem, name, &st, nextoff);
		}
		if (entsize > rem)
			break;

		p += entsize;
		rem -= entsize;

		d->entry = NULL;
		d->offset = nextoff;
	}
	err = 0;
error:
	if (err && rem == size)
		fuse_reply_err(req, err);
	else
		fuse_reply_buf(req, buf, size - rem);
	free(buf);
}

static void
czfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
	     struct fuse_file_info *fi)
{
	do_readdir(req, ino, size, off, fi, 0);
}

static void
czfs_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
		 struct fuse_file_info *fi)
{
	do_readdir(req, ino, size, off, fi, 1);
}

static bool
has_safetensor_suffix(const char *filename)
{
	const char *suffix = ".safetensors";
	size_t len_filename = strlen(filename);
	size_t len_suffix = strlen(suffix);
	if (len_filename < len_suffix)
		return false;
	return strcmp(filename + len_filename - len_suffix, suffix) == 0;
}

static void
czfs_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode,
	    struct fuse_file_info *fi)
{
	struct czfs_filep *fh = malloc(sizeof(*fh));
	struct fuse_entry_param e;
	int err;

	fh->fd = openat(czfs_inode(req, parent)->fd, name,
			(fi->flags | O_CREAT) & ~O_NOFOLLOW, mode);
	if (fh->fd == -1) {
		fuse_reply_err(req, errno);
		return;
	}
	if (has_safetensor_suffix(name)) {
		fh->state = CHEEZ_INIT;
	} else {
		fh->state = CHEEZ_IGNORE;
	}

	fi->fh = (uint64_t)fh;
	RB_INIT(&fh->tensors);

	err = do_lookup(req, parent, name, &e);
	if (err) {
		fuse_reply_err(req, err);
		return;
	}

	fuse_reply_create(req, &e, fi);
}

static void
czfs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	char buf[64];
	struct czfs_filep *fh = malloc(sizeof(*fh));

	sprintf(buf, "/proc/self/fd/%i", czfs_inode(req, ino)->fd);
	fh->fd = open(buf, fi->flags & ~O_NOFOLLOW);
	if (fh->fd == -1) {
		fuse_reply_err(req, errno);
		return;
	}
	fh->state = CHEEZ_INIT;
	fi->fh = (uint64_t)fh;
	RB_INIT(&fh->tensors);

	if (fi->flags & O_DIRECT)
		fi->direct_io = 1;

	fuse_reply_open(req, fi);
}

static void
czfs_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	close(czfs_filep(fi)->fd);
	free((void *)fi->fh);
	fuse_reply_err(req, 0);
	return;
}

static void
czfs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
	  struct fuse_file_info *fi)
{
	struct fuse_bufvec buf = FUSE_BUFVEC_INIT(size);

	buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
	buf.buf[0].fd = czfs_filep(fi)->fd;
	buf.buf[0].pos = offset;

	fuse_reply_data(req, &buf, FUSE_BUF_SPLICE_MOVE);
}

static int
czfs_parse_json(struct fuse_file_info *fi, char *buf)
{
	json_error_t error;
	char *json = malloc(czfs_filep(fi)->n + 1);
	json[czfs_filep(fi)->n] = '\0';
	memcpy(json, buf, czfs_filep(fi)->n);
	fprintf(stderr, "%s\n", json);
	json_t *root = json_loads(json, 0, &error);
	void *iter;
	if (!root) {
		fprintf(stderr, "error: on line %d: %s\n", error.line,
			error.text);
		return 1;
	}
	if (!json_is_object(root)) {
		fprintf(stderr, "error: root is not an object\n");
		return 1;
	}
	iter = json_object_iter(root);
	while (iter) {
		const char *key = json_object_iter_key(iter);
		fprintf(stderr, "key=%s\n", key);
		char *dupkey = strdup(key);
		json_t *value = json_object_iter_value(iter);
		if (strcmp(key, "__metadata__") != 0) {
			struct czfs_tensor *tensor = malloc(sizeof(*tensor));
			tensor->key = dupkey;
			tensor->fd = czfs_filep(fi)->fd;
			json_t *data_offsets =
			    json_object_get(value, "data_offsets");
			if (!json_is_array(data_offsets)) {
				fprintf(
				    stderr,
				    "error: data_offsets is not an array\n");
				free(tensor);
				free(dupkey);
				return 1;
			}
			size_t i;
			for (i = 0; i < json_array_size(data_offsets); i++) {
				json_t *o = json_array_get(data_offsets, i);
				if (json_is_integer(o)) {
					size_t v =
					    (size_t)json_integer_value(o);
					tensor->data_offsets[i] = v;
				} else {
					fprintf(stderr,
						"Non-integer value in array at "
						"index %zu\n",
						i);
					free(tensor);
					free(dupkey);
					return 1;
				}
			}
			fprintf(stderr, "dump key=%s offset=[%zu, %zu]\n",
				tensor->key, tensor->data_offsets[0],
				tensor->data_offsets[1]);
			RB_INSERT(czfs_ttree, &czfs_filep(fi)->tensors, tensor);
		} else
			free(dupkey);
		iter = json_object_iter_next(root, iter);
	}
	return 0;
}

static void
czfs_write_buf(fuse_req_t req, fuse_ino_t ino, struct fuse_bufvec *in_buf,
	       off_t off, struct fuse_file_info *fi)
{
	ssize_t res;
	size_t len = fuse_buf_size(in_buf);
	fprintf(stderr, "state=%d len=%zu\n", czfs_filep(fi)->state, len);
	switch (czfs_filep(fi)->state) {
	case CHEEZ_INIT: {
		char *buf = malloc(len);
		struct fuse_bufvec tmp = FUSE_BUFVEC_INIT(len);
		tmp.buf[0].flags = 0;
		tmp.buf[0].mem = buf;
		tmp.buf[0].size = len;
		tmp.buf[0].pos = 0;
		res = fuse_buf_copy(&tmp, in_buf, 0);
		if (res != len) {
			if (res < 0) {
				fuse_reply_err(req, -res);
				free(buf);
				return;
			} else {
				len = res;
				fprintf(stderr, "ignore res=%zu\n",
					(size_t)res);
				czfs_filep(fi)->state = CHEEZ_IGNORE;
				goto flush_init;
			}
		}
		if (len == 8) {
			uint64_t n = *(uint64_t *)buf;
			czfs_filep(fi)->n = le64toh(n);
			czfs_filep(fi)->state = CHEEZ_PREPARE;
			goto flush_init;
		} else if (len > 8) {
			czfs_filep(fi)->n = le64toh(*(uint64_t *)(buf));
			if (len == czfs_filep(fi)->n + 8) {
				char *metadata = buf + 8;
				if (czfs_parse_json(fi, metadata)) {
					czfs_filep(fi)->state = CHEEZ_IGNORE;
					goto flush_init;
				}
				czfs_filep(fi)->state = CHEEZ_BULK;
			} else {
				czfs_filep(fi)->state = CHEEZ_IGNORE;
			}
			goto flush_init;
		} else {
			czfs_filep(fi)->state = CHEEZ_IGNORE;
			goto flush_init;
		}
	flush_init:
		res = pwrite(czfs_filep(fi)->fd, buf, len, off);
		if (res < 0) {
			fuse_reply_err(req, -res);
		} else {
			fuse_reply_write(req, res);
		}
		free(buf);
		return;
	}
	case CHEEZ_PREPARE: {
		char *buf = malloc(len);
		struct fuse_bufvec tmp = FUSE_BUFVEC_INIT(len);
		tmp.buf[0].flags = 0;
		tmp.buf[0].mem = buf;
		tmp.buf[0].size = 8;
		tmp.buf[0].pos = 0;
		res = fuse_buf_copy(&tmp, in_buf, 0);
		if (res != len) {
			if (res < 0) {
				fuse_reply_err(req, -res);
				free(buf);
				return;
			} else {
				len = res;
				czfs_filep(fi)->state = CHEEZ_IGNORE;
				goto flush_prepare;
			}
		}

		if (len != czfs_filep(fi)->n) {
			czfs_filep(fi)->state = CHEEZ_IGNORE;
			goto flush_prepare;
		}
		if (czfs_parse_json(fi, buf)) {
			czfs_filep(fi)->state = CHEEZ_IGNORE;
			goto flush_prepare;
		}
		czfs_filep(fi)->state = CHEEZ_BULK;
	flush_prepare:
		res = pwrite(czfs_filep(fi)->fd, buf, len, off);
		if (res < 0) {
			fuse_reply_err(req, -res);
		} else {
			fuse_reply_write(req, res);
		}
		free(buf);
		return;
	}
	default:
		break;
	}
	struct fuse_bufvec out_buf = FUSE_BUFVEC_INIT(fuse_buf_size(in_buf));

	out_buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
	out_buf.buf[0].fd = czfs_filep(fi)->fd;
	out_buf.buf[0].pos = off;

	res = fuse_buf_copy(&out_buf, in_buf, 0);
	if (res < 0) {
		fprintf(stderr, "fuse_buf_copy res=%s\n", strerror(-res));
		fuse_reply_err(req, -res);
		return;
	}
	fprintf(stderr, "fuse_reply_write %zu\n", (size_t)res);
	fuse_reply_write(req, (size_t)res);
}

static void
czfs_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
	    fuse_ino_t newparent, const char *newname, unsigned int flags)
{
	int res;

	if (flags) {
		fuse_reply_err(req, EINVAL);
		return;
	}

	res = renameat(czfs_inode(req, parent)->fd, name,
		       czfs_inode(req, newparent)->fd, newname);

	if (res == -1) {
		fuse_reply_err(req, errno);
		return;
	}

	fuse_reply_err(req, 0);
}

static void
czfs_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	int res;

	res = unlinkat(czfs_inode(req, parent)->fd, name, 0);

	fuse_reply_err(req, res == -1 ? errno : 0);
}

static void
czfs_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	struct czfs_data *data = czfs_data(req);
	struct czfs_inode *inode = czfs_inode(req, ino);

	pthread_mutex_lock(&data->mutex);
	assert(inode->refcount >= nlookup);
	inode->refcount -= nlookup;
	if (inode->refcount == 0) {
		close(inode->fd);
		RB_REMOVE(czfs_itree, &data->head, inode);
		free(inode);
	}
	pthread_mutex_unlock(&data->mutex);
	fuse_reply_none(req);
}

static struct fuse_lowlevel_ops czfs_oper = {
    .init = czfs_init,
    .lookup = czfs_lookup,
    .mkdir = czfs_mkdir,
    .getattr = czfs_getattr,
    .setattr = czfs_setattr,
    .opendir = czfs_opendir,
    .readdir = czfs_readdir,
    .readdirplus = czfs_readdirplus,
    .create = czfs_create,
    .open = czfs_open,
    .release = czfs_release,
    .read = czfs_read,
    .write_buf = czfs_write_buf,
    .rename = czfs_rename,
    .unlink = czfs_unlink,
    .forget = czfs_forget,
};

int
main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_cmdline_opts opts;
	struct czfs_data data;
	memset(&opts, 0, sizeof(opts));
	memset(&data, 0, sizeof(data));

	if (fuse_parse_cmdline(&args, &opts) != 0 || !opts.mountpoint) {
		fprintf(stderr, "Usage: %s <mountpoint>\n", argv[0]);
		fuse_opt_free_args(&args);
		return 1;
	}

	if (fuse_opt_parse(&args, &data, czfs_opts, NULL) == -1)
		return 1;
	if (!data.source) {
		fprintf(stderr, "Missing source\n");
		return 1;
	}

	struct fuse_session *se =
	    fuse_session_new(&args, &czfs_oper, sizeof(czfs_oper), &data);
	if (!se) {
		free(opts.mountpoint);
		fuse_opt_free_args(&args);
		return 1;
	}

	fuse_set_signal_handlers(se);

	if (fuse_session_mount(se, opts.mountpoint) != 0) {
		fuse_session_destroy(se);
		free(opts.mountpoint);
		fuse_opt_free_args(&args);
		return 1;
	}

	fuse_daemonize(opts.foreground);
	int ret = fuse_session_loop_mt(se, NULL);

	fuse_session_unmount(se);
	fuse_remove_signal_handlers(se);
	fuse_session_destroy(se);
	free(opts.mountpoint);
	fuse_opt_free_args(&args);

	if (data.root.fd >= 0)
		close(data.root.fd);

	return ret ? 1 : 0;
}
