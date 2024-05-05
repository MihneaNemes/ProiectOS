#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <ctype.h>

#define MAX_PATH_LENGTH 1024
#define MAX_METADATA_LENGTH 512

#define SUSPICIOUS_LINES_THRESHOLD 3
#define SUSPICIOUS_WORDS_THRESHOLD 1000
#define SUSPICIOUS_CHARACTERS_THRESHOLD 2000

#define PIPE_READ_END 0
#define PIPE_WRITE_END 1

bool contains_non_ascii(const char *str) {
    while (*str) {
        if (!isascii(*str))
            return true;
        str++;
    }
    return false;
}

bool contains_dangerous_keywords(const char *str) {
    const char *keywords[] = {"corrupted", "dangerous", "risk", "attack", "malware", "malicious"};
    const int num_keywords = sizeof(keywords) / sizeof(keywords[0]);

    for (int i = 0; i < num_keywords; ++i) {
        if (strstr(str, keywords[i]) != NULL)
            return true;
    }
    return false;
}

void isolate_file(const char *file_path, const char *isolated_space_dir) {
    char mv_cmd[MAX_PATH_LENGTH];
    snprintf(mv_cmd, sizeof(mv_cmd), "mv %s %s", file_path, isolated_space_dir);
    system(mv_cmd);
}

void evaluate_file(const char *file_path, int pipe_fd, const char *isolated_space_dir) {
    int file_fd = open(file_path, O_RDONLY);
    if (file_fd == -1) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    char buffer[MAX_METADATA_LENGTH];
    int num_lines = 0;
    int num_words = 0;
    int num_characters = 0;

    ssize_t bytes_read;
    while ((bytes_read = read(file_fd, buffer, sizeof(buffer))) > 0) {
        for (ssize_t i = 0; i < bytes_read; ++i) {
            if (buffer[i] == '\n') {
                num_lines++;
            } else if (isspace(buffer[i])) {
                num_words++;
            }
            num_characters++;
        }
    }

    close(file_fd);

    bool is_suspicious = false;
    if (num_lines < SUSPICIOUS_LINES_THRESHOLD &&
        num_words > SUSPICIOUS_WORDS_THRESHOLD &&
        num_characters > SUSPICIOUS_CHARACTERS_THRESHOLD) {
        is_suspicious = true;
    } else {
        char content[MAX_METADATA_LENGTH];
        snprintf(content, sizeof(content), "SAFE");
        write(pipe_fd, content, strlen(content) + 1);
        close(pipe_fd);
        exit(EXIT_SUCCESS);
    }

    file_fd = open(file_path, O_RDONLY);
    if (file_fd == -1) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    char read_buffer[MAX_METADATA_LENGTH];
    ssize_t read_bytes;
    while ((read_bytes = read(file_fd, read_buffer, sizeof(read_buffer))) > 0) {
        if (contains_non_ascii(read_buffer) || contains_dangerous_keywords(read_buffer)) {
            is_suspicious = true;
            break;
        }
    }

    close(file_fd);

    if (is_suspicious) {
        isolate_file(file_path, isolated_space_dir);
    }

    char result[MAX_METADATA_LENGTH];
    snprintf(result, sizeof(result), "%s", is_suspicious ? file_path : "SAFE");

    write(pipe_fd, result, strlen(result) + 1);
    close(pipe_fd);
    exit(EXIT_SUCCESS);
}

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

void captureDirMetadataRecursive(const char *dir_path, char *snapshot_content, const char *isolated_space_dir) {
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
                captureDirMetadataRecursive(full_path, snapshot_content, isolated_space_dir);
            } else {
                if ((file_stat.st_mode & S_IRWXU) == 0 && (file_stat.st_mode & S_IRWXG) == 0 && (file_stat.st_mode & S_IRWXO) == 0) {
                    pid_t child_pid = fork();
                    if (child_pid == 0) {
                        char cmd[MAX_PATH_LENGTH];
                        snprintf(cmd, sizeof(cmd), "./verify_for_malicious.sh %s", full_path);
                        int ret = system(cmd);
                        if (ret != 0) {
                            char mv_cmd[MAX_PATH_LENGTH];
                            snprintf(mv_cmd, sizeof(mv_cmd), "mv %s %s", full_path, isolated_space_dir);
                            system(mv_cmd);
                        }
                        exit(0);
                    } else if (child_pid == -1) {
                        perror("Failed to fork a child process");
                        return;
                    }
                }
                captureFileMetadata(full_path, snapshot_content);
            }
        }
    }
    closedir(dir);
}

void captureDirMetadata(const char *dir_path, const char *output_dir, const char *isolated_space_dir) {
    char snapshot_content[MAX_METADATA_LENGTH] = "";

    captureDirMetadataRecursive(dir_path, snapshot_content, isolated_space_dir);

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

void updateSnapshot(const char *output_dir, const char *isolated_space_dir, char *argv[], int start_index, int end_index) {
    int i;
    for (i = start_index; i < end_index; i++) {
        char *dir_path = argv[i];
        if (strcmp(argv[i - 1], "-s") == 0) {
            continue;
        }
        pid_t child_pid = fork();
        if (child_pid == 0) {
            captureDirMetadata(dir_path, output_dir, isolated_space_dir);
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
    if (argc < 4 || argc > 13) {
        printf("Usage: %s -o <output_dir> -s <isolated_space_dir> <dir1> <dir2> ... <dirN>\n", argv[0]);
        return 1;
    }

    char *output_dir = NULL;
    char *isolated_space_dir = NULL;
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
        } else if (strcmp(argv[i], "-s") == 0) {
            if (i + 1 < argc) {
                isolated_space_dir = argv[i + 1];
                i++;
            } else {
                printf("Missing isolated space directory path after -s option.\n");
                return 1;
            }
        }
    }

    int start_index = 1;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            start_index = i + 3;
            break;
        }
    }

    updateSnapshot(output_dir, isolated_space_dir, argv, start_index, argc);

    return 0;
}
