#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

unsigned char *calculateHash(const char *path) {
  MD5_CTX md5Context;
  unsigned char *digest = (unsigned char *)malloc(MD5_DIGEST_LENGTH);
  unsigned char data[1024];
  size_t bytesRead;

  MD5_Init(&md5Context);

  FILE *(*original_fopen_ptr)(const char *, const char *);
  original_fopen_ptr = dlsym(RTLD_NEXT, "fopen");
  FILE *original_fopen = (*original_fopen_ptr)(path, "rb");

  if (original_fopen == NULL) {
    return NULL;
  }

  while ((bytesRead = fread(data, 1, sizeof(data), original_fopen)) != 0) {
    MD5_Update(&md5Context, data, bytesRead);
  }

  fclose(original_fopen);

  MD5_Final(digest, &md5Context);

  return digest;
}

void logFile(int uid, const char *path, int action, int isDenied) {
  time_t rawtime = time(NULL);
  struct tm tm = *localtime(&rawtime);

  unsigned char *digest = calculateHash(path);

  FILE *(*original_fopen_ptr)(const char *, const char *);
  original_fopen_ptr = dlsym(RTLD_NEXT, "fopen");
  FILE *lf = (*original_fopen_ptr)("file_logging.log", "a");

  if (lf == NULL) {
    printf("Error opening file");
    exit(0);
  }

  fprintf(lf, "%u %s %d-%d-%d %02d:%02d:%02d %d %d ", uid, realpath(path, NULL), tm.tm_mday,
          tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, action, isDenied);

  if (digest != NULL) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
      fprintf(lf, "%02x", digest[i]);
    }
  } else
    fprintf(lf, "0");

  fprintf(lf, "\n");

  fclose(lf);

  return;
}

char *findPath(FILE *fp) {
  int MAXSIZE = 0xFFF;
  char proclnk[MAXSIZE];
  char *fileName = (char *)malloc(sizeof(char) * MAXSIZE);
  int fno;
  ssize_t r;

  if (fp != NULL) {
    fno = fileno(fp);
    sprintf(proclnk, "/proc/self/fd/%d", fno);
    r = readlink(proclnk, fileName, MAXSIZE);

    if (r < 0) {
      printf("failed to readlink\n");
      return NULL;
    }

    fileName[r] = '\0';

    return fileName;
  }
  return NULL;
}

FILE *fopen(const char *path, const char *mode) {
  int action, isDenied;
  isDenied = 0;

  if (access(path, F_OK) == 0) { //file exists
    action = 1;
  } else { //file does not exist
    action = 0;
  }

  FILE *(*original_fopen_ptr)(const char *, const char *);
  original_fopen_ptr = dlsym(RTLD_NEXT, "fopen");
  FILE *original_fopen = (*original_fopen_ptr)(path, mode);

  if (original_fopen == NULL) { //error opening file
    if (errno == EACCES || errno == EPERM) { //have no permission to open file
      isDenied = 1;
    } else if (errno == ENOENT) { //file does not exist (when opening with read mode)
      action = 1;
    } else {
      printf("UNKNOWN ERROR!\n");
    }
  }

  int uid = getuid();

  logFile(uid, path, action, isDenied);

  return original_fopen;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
  size_t (*original_fwrite_ptr)(const void *, size_t, size_t, FILE *);
  original_fwrite_ptr = dlsym(RTLD_NEXT, "fwrite");
  size_t original_fwrite = (*original_fwrite_ptr)(ptr, size, nmemb, stream);

  int isDenied;

  const char *path = findPath(stream);

  if (access(path, W_OK) == 0)
    isDenied = 0;
  else
    isDenied = 1;

  int fd = fileno(stream);
  int mode = fcntl(fd, F_GETFL);

  if (mode == 32768)  //read mode
    isDenied = 1;

  int uid = getuid();

  fflush(stream);

  logFile(uid, path, 2, isDenied);

  return original_fwrite;
}
