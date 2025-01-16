#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main() {
  int i;
  size_t bytes;
  FILE *file;
  char filenames[10][7] = {"file_0", "file_1", "file_2", "file_3", "file_4",
                           "file_5", "file_6", "file_7", "file_8", "file_9"};

  //create files and write
  for (i = 0; i < 10; i++) {
    file = fopen(filenames[i], "w");
    if (file == NULL)
      printf("fopen error\n");
    else {
      bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
      fclose(file);
    }
  }

  //open existing files and append
  for (i = 0; i < 10; i++) {
    file = fopen(filenames[i], "a");
    if (file == NULL)
      printf("fopen error\n");
    else {
      bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
      fclose(file);
    }
  }

  //open existing file in read mode and try to write
  file = fopen("file_0", "r");
  if (file == NULL)
    printf("fopen error\n");
  else {
    char myString[] = "Trying to write while in read mode...";
    bytes = fwrite(myString, strlen(myString), 1, file);
    fclose(file);
  }

  //try to open and read file that does not exist
  file = fopen("nonexistent.txt", "r");
  if (file != NULL) {
    printf("nonexistent.txt opened\n");
    fclose(file);
  }

  // uid_t new_uid = 1001;
  // setuid(new_uid); //run using sudo

  //try to open and read 7 different files without read permission (malicious user)
  for (i = 0; i < 7; i++) {
    chmod(filenames[i], 0);
    file = fopen(filenames[i], "r");
    if (file != NULL) fclose(file);
  }

  //try to open and write to 3 different files without write permission (only read permission)
  for (i = 7; i < 10; i++) {
    chmod(filenames[i], S_IRUSR);
    file = fopen(filenames[i], "w");
    if (file != NULL) {
      bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
      fclose(file);
    }
  }

  return 0;
}
