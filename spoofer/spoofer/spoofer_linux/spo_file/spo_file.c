#include "../../spoofer_system/spoofer.h"
#include "../spo_linux.h"




SPO_RET_VALUE spo_open(const char *file, int file_flg, int perm)
{
    int fd = -1;

    if (file == NULL) return SPO_FAILURE;

    if (perm <= -1) {
        fd = open(file, file_flg);
    }else {
        fd = open(file, file_flg, perm);
    }

    return fd;
}


size_t spo_read(int fd, void *buf, size_t n_size)
{
    if (fd < 0 || buf == NULL || n_size <= 0) return 0;

    size_t size = read(fd, buf, n_size);

    if (size == 0) return 0;

    return size;
}


SPO_RET_VALUE spo_close(int fd)
{
    if (fd < 0) return SPO_OK;

    return close(fd);
}


/*  */
ssize_t spo_write(int fd, const void *buf, size_t size)
{
    ssize_t s = 0;

    if (buf == NULL || size <= 0 || fd < 0) return 0;

    s = write(fd, buf, size);

    return s;
}


/*  */
FILE *spo_fopen(const char *file_name, const char *modes)
{
    FILE *fp;

    if (file_name == NULL || modes == NULL) return NULL;

    fp = fopen(file_name, modes);

    return fp;
}


SPO_RET_VALUE spo_fclose(FILE *fp)
{
    if (fp == NULL) return SPO_OK;

    return fclose(fp);
}

/*
 *  get the file size.
 *
 *  @param file_path, the file's path and name.
 *
 *  @return the file's size.
 *
 *  status :finished, tested.
 */

size_t spo_file_size(const char *file_path)
{
    struct stat info;

    if (file_path == NULL)  return 0;

    if ((stat(file_path, &info)) == -1) return 0;

    if (!S_ISREG(info.st_mode)) return 0;

    return info.st_size;
}


/*
 *  read the dns's data that in file
 *
 *  @param file_path, is the file path that inclue the file's name.
 *
 *  @param buf, we read the data that saved in buf.
 *
 *  @param n, the data len we read.
 *
 *  @return the data length we readed.
 *
 *  status :finished, tested.
 */

size_t spo_read_file_data(const char *file_path, void *buf)
{
    if (file_path == NULL || buf == NULL) return 0;

    int fd = -1;
    int ret = -1;

    if ((fd = spo_open(file_path, O_RDONLY, -1)) == SPO_FAILURE) return 0;

    if ((ret = spo_read(fd, buf, spo_file_size(file_path))) == 0) return 0;

    spo_close(fd);

    return ret;
}


/**
 *
 *  merger the path and the file name.
 *
 *  if the file is a regular file, return ok.
 *
 * */

SPO_RET_STATUS spo_merg_absol_path_name(const char *path, const char *name, char *absol_name)
{
    struct stat info;

    if (name == NULL || path == NULL || absol_name == NULL) return SPO_FAILURE;

    memset(absol_name, '\0', SPO_MAX_FILE_NAME_LEN);
    memset(&info, '\0', sizeof(struct stat));

    if (strlen(path) + strlen(name) >= SPO_MAX_FILE_NAME_LEN) return SPO_FAILURE;

    sprintf(absol_name, "%s/%s", path, name);
#if SPO_DEBUG
    printf("%s\n", absol_name);
#endif

    stat(absol_name, &info);

    if (S_ISREG(info.st_mode)) return SPO_OK;

    return SPO_FAILURE;
}
