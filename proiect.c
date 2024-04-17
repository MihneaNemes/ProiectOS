#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>

#define MAX_PATH_LENGTH 1024
#define MAX_METADATA_LENGTH 512

void captureFileMetadata(const char *file_path, char *snapshot_content) {
    struct stat file_stat;
    if (stat(file_path, &file_stat) == -1) {
        perror("Unable to get file status");
        return;
    }

    char type = 'F';
    char time_str[MAX_METADATA_LENGTH];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&file_stat.st_mtime));

    char entry_str[MAX_METADATA_LENGTH];
    snprintf(entry_str, sizeof(entry_str), "%s\t%c\t%d\t%s\n", file_path, type,
             (int)file_stat.st_size, time_str);

    strcat(snapshot_content, entry_str);
}

void captureDirMetadataRecursive(const char *dir_path, char *snapshot_content) {
    struct dirent *entry;
    DIR *dir = opendir(dir_path);

    if (dir == NULL) {
        perror("Unable to open directory");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            char full_path[MAX_PATH_LENGTH];
            snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);

            struct stat file_stat;
            if (stat(full_path, &file_stat) == -1) {
                perror("Unable to get file status");
                continue;
            }

            if (S_ISDIR(file_stat.st_mode)) {
                captureDirMetadataRecursive(full_path, snapshot_content);
            } else {
                captureFileMetadata(full_path, snapshot_content);
            }
        }
    }
    closedir(dir);
}

void captureDirMetadata(const char *dir_path, const char *output_dir) {
    char snapshot_content[MAX_METADATA_LENGTH] = "";

    captureDirMetadataRecursive(dir_path, snapshot_content);

    char snapshot_path[MAX_PATH_LENGTH];
    snprintf(snapshot_path, sizeof(snapshot_path), "%s/Snapshot_%s.txt", output_dir, dir_path);

    int snapshot_fd = open(snapshot_path, O_RDWR | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (snapshot_fd == -1) {
        perror("Unable to open snapshot file for writing");
        return;
    }

    char header[] = "The order is: Name, Type, Size, Last Modified\n";
    write(snapshot_fd, header, strlen(header));
    write(snapshot_fd, snapshot_content, strlen(snapshot_content));

    close(snapshot_fd);
    printf("Snapshot for directory %s appended successfully.\n", dir_path);
}

void updateSnapshot(const char *output_dir, char *argv[], int start_index, int end_index) {
    int i;
    for (i = start_index; i < end_index; i++) {
        char *dir_path = argv[i];
        pid_t child_pid = fork();
        if (child_pid == 0) {
            captureDirMetadata(dir_path, output_dir);
            exit(0);
        } else if (child_pid == -1) {
            perror("Failed to fork a child process");
            return;
        }
    }

    int status;
    pid_t pid;
    while ((pid = wait(&status)) > 0) {
        if (WIFEXITED(status)) {
            printf("Child Process %d terminated with PID %d and exit code %d.\n", pid, pid, WEXITSTATUS(status));
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3 || argc > 12) {
        printf("Usage: %s -o <output_dir> <dir1> <dir2> ... <dirN>\n", argv[0]);
        return 1;
    }

    char *output_dir = NULL;
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 < argc) {
                output_dir = argv[i + 1];
                i++;
            } else {
                printf("Missing output directory path after -o option.\n");
                return 1;
            }
        }
    }

    int start_index = 1;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            start_index = i + 2;
            break;
        }
    }

    updateSnapshot(output_dir, argv, start_index, argc);

    return 0;
}
