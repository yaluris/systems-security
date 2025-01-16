#define _GNU_SOURCE

#include <limits.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct entry {
  int uid;
  int checked;
  char path[PATH_MAX];
  unsigned char fingerprint[MD5_DIGEST_LENGTH * 2 + 1];
  struct entry *next;
} entry;

void printList(struct entry *head) {
  if (head == NULL) 
    printf("Empty List\n");

  entry *current = head;

  while (current != NULL) {
    printf("\n%d %s %s", current->uid, current->path, current->fingerprint);
    current = current->next;
  }
}

void usage(void) {
  printf(
      "\n"
      "usage:\n"
      "\t./acmonitor \n"
      "Options:\n"
      "-m, Prints malicious users\n"
      "-i <filename>, Prints table of users that modified "
      "the file <filename> and the number of modifications\n"
      "-h, Help message\n\n");

  exit(1);
}

void list_unauthorized_accesses(FILE *log) {
  int uid;
  char file[PATH_MAX + 1];
  int day, month, year, hour, min, sec;
  int action;
  int isDenied;
  ssize_t read;
  size_t size = 0;
  char *line = NULL;

  entry *newNode = NULL;
  entry *deniedAccesses = NULL;
  entry *curr = NULL;

  while ((read = getline(&line, &size, log)) != EOF) {
    sscanf(line, "%d %s %d-%d-%d %02d:%02d:%02d %d %d", &uid, file, &day, &month, &year, &hour,
           &min, &sec, &action, &isDenied);

    if (isDenied == 1) {
      if (deniedAccesses == NULL) {
        deniedAccesses = (entry *)malloc(sizeof(entry));
        deniedAccesses->uid = uid;
        strcpy(deniedAccesses->path, file);
        deniedAccesses->next = NULL;
      } 
      else {
        newNode = (entry *)malloc(sizeof(entry));
        newNode->uid = uid;
        strcpy(newNode->path, file);

        curr = deniedAccesses;
        while (curr->next != NULL) {
          curr = curr->next;
        }

        curr->next = newNode;
      }
    }
  }

  //printList(deniedAccesses);

  entry *denAc = deniedAccesses;
  char files[6][PATH_MAX];
  int count, exists;
  entry *prev = malloc(sizeof(entry));

  while (denAc != NULL) {
    count = 1;
    curr = denAc;

    uid = curr->uid;
    strcpy(files[0], curr->path);

    while (curr->next != NULL) {
      exists = 0;
      prev = curr;
      curr = curr->next;

      if (curr->uid == uid) {
        if (count < 7) {
          for (int i = 0; i < count; i++) {
            if (strcmp(curr->path, files[i]) == 0) {
              exists = 1;
              break;
            }
          }
        }

        if (exists != 1) {
          count++;

          if (count == 7) {
            printf("UID %d is a malicious user.\n", uid);
          } 
          else if (count < 7) {
            strcpy(files[count - 1], curr->path);
          }
        }

        prev->next = curr->next;
        free(curr);
        curr = prev;
      }
    }

    denAc = denAc->next;
  }

  return;
}

void list_file_modifications(FILE *log, char *file_to_scan) {
  int uid;
  char file[PATH_MAX + 1];
  int day, month, year, hour, min, sec;
  int action;
  int isDenied;
  unsigned char fingerprint[MD5_DIGEST_LENGTH * 2 + 1];  //fingerprint is written to log file using x02, so double the size of MD5_DIGEST_LENGTH plus 1 for \0
  ssize_t read;
  size_t size = 0;
  char *line = NULL;

  entry *fileAccesses = NULL;
  entry *curr = NULL;
  entry *newNode = NULL;

  if (access(file_to_scan, F_OK) != 0) {
    printf("File does not exist.\n");
    return;
  }

  while ((read = getline(&line, &size, log)) != EOF) {
    sscanf(line, "%d %s %d-%d-%d %02d:%02d:%02d %d %d %s", &uid, file, &day, &month, &year, &hour,
           &min, &sec, &action, &isDenied, fingerprint);

    file_to_scan = realpath(file_to_scan, NULL);

    if (strcmp(file, file_to_scan) == 0) {
      if (fileAccesses == NULL) {
        fileAccesses = (entry *)malloc(sizeof(entry));

        fileAccesses->uid = uid;
        fileAccesses->checked = 0;
        strcpy(fileAccesses->path, file);
        strcpy(fileAccesses->fingerprint, fingerprint);
        fileAccesses->next = NULL;
      } 
      else {
        newNode = (entry *)malloc(sizeof(entry));

        newNode->uid = uid;
        newNode->checked = 0;
        strcpy(newNode->path, file);
        strcpy(newNode->fingerprint, fingerprint);

        curr = fileAccesses;
        while (curr->next != NULL) {
          curr = curr->next;
        }

        curr->next = newNode;
      }
    }
  }

  if (fileAccesses == NULL) {
    printf("File %s does not appear in the log file.\n", file_to_scan);
  }

  //printList(fileAccesses);

  int count;
  entry *fileAc = fileAccesses;
  entry *prev = malloc(sizeof(entry));
  entry *tmpFileAc = NULL;

  while (fileAc != NULL) {
    if (fileAc->checked == 1) {
      tmpFileAc = fileAc;
      fileAc = fileAc->next;
      continue;
    }

    count = 0;

    if (tmpFileAc != NULL && strcmp(fileAc->fingerprint, tmpFileAc->fingerprint) != 0) count++;

    curr = fileAc;

    uid = curr->uid;

    while (curr->next != NULL) {
      prev = curr;
      curr = curr->next;

      if (curr->uid == uid) {
        if (strcmp(curr->fingerprint, prev->fingerprint) != 0) count++;
        curr->checked = 1;
      }
    }
    printf("UID %d modified the %s file %d time(s).\n", uid, file_to_scan, count);

    tmpFileAc = fileAc;

    fileAc = fileAc->next;
  }

  return;
}

int main(int argc, char *argv[]) {
  int ch;
  FILE *log;

  if (argc < 2) usage();

  log = fopen("./file_logging.log", "r");
  
  if (log == NULL) {
    printf("Error opening log file.\n");
    return 1;
  }

  while ((ch = getopt(argc, argv, "hi:m")) != -1) {
    switch (ch) {
      case 'i':
        list_file_modifications(log, optarg);
        break;
      case 'm':
        list_unauthorized_accesses(log);
        break;
      default:
        usage();
    }
  }

  fclose(log);
  argc -= optind;
  argv += optind;

  return 0;
}
