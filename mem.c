#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>

void set_oom_adj(int adj) {
    char path[] = "/proc/self/oom_score_adj";
    FILE *f = fopen(path, "w");
    if (!f) {
        perror("Failed to open oom_score_adj (run as root?)");
        return;
    }
    fprintf(f, "%d", adj);
    fclose(f);
    printf("PID %d: Set oom_score_adj to %d\n", getpid(), adj);
}

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 3) {
        printf("Usage: %s <MB> [oom_score_adj]\n", argv[0]);
        printf("Example: %s 500 -500  (Allocates 500MB, highly protected)\n", argv[0]);
        return 1;
    }

    long mb = atol(argv[1]);
    int oom_adj = (argc == 3) ? atoi(argv[2]) : 0;

    // Apply the priority adjustment
    set_oom_adj(oom_adj);

    long long bytes = mb * 1024LL * 1024LL;
    long long num_pages = bytes / 4096;

    char *p = malloc(bytes);
    if (!p) {
        perror("malloc");
        return 1;
    }

    printf("PID %d: Allocating and initializing %ld MB...\n", getpid(), mb);
    for (long long i = 0; i < bytes; i += 4096) {
        p[i] = 1;
    }

    srand(time(NULL));

    volatile char sum = 0;
    while (1) {
        for (int i = 0; i < 5000; i++) {
            long long random_page = rand() % num_pages;
            long long offset = random_page * 4096;
            sum += p[offset];
            p[offset] = sum;
        }
        usleep(100);
    }

    return 0;
}