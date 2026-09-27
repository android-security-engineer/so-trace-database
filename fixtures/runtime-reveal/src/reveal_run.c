#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <libreveal.so> <trace.json>\n", argv[0]);
        return 2;
    }

    void *lib = dlopen(argv[1], RTLD_NOW);
    if (lib == NULL) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 1;
    }

    uint32_t (*mix)(const uint8_t *, size_t) = dlsym(lib, "sotrace_runtime_mix");
    if (mix == NULL) {
        fprintf(stderr, "dlsym: %s\n", dlerror());
        return 1;
    }

    /* Input stays in this runner. The shared object only sees the pointer. */
    const uint8_t input[] = {
        'l', 'a', 'n', 'e', '-', '7', '-', 's', 'e', 's', 's', 'i', 'o', 'n'
    };
    uint32_t fact = mix(input, sizeof input);

    FILE *out = fopen(argv[2], "w");
    if (out == NULL) {
        perror("fopen");
        return 1;
    }
    fprintf(out,
        "{\n"
        "  \"threads\": [{\n"
        "    \"thread_id\": 1, \"pthread_id\": null, \"parent_thread_id\": 0,\n"
        "    \"create_step\": 0, \"exit_step\": null, \"name\": \"reveal\",\n"
        "    \"stack_base\": 0, \"stack_size\": 0, \"tls_addr\": 0,\n"
        "    \"is_jni_attached\": false\n"
        "  }],\n"
        "  \"instructions\": [{\n"
        "    \"seq\": 1, \"thread_id\": 1, \"address\": 4096,\n"
        "    \"timestamp\": null, \"is_branch\": false, \"branch_taken\": false,\n"
        "    \"opcode\": null\n"
        "  }],\n"
        "  \"register_deltas\": [{\n"
        "    \"seq\": 1, \"change_mask\": 1, \"values\": [%u]\n"
        "  }]\n"
        "}\n",
        fact);
    if (fclose(out) != 0) {
        perror("fclose");
        return 1;
    }

    /* One line: the runtime fact, decimal. */
    printf("%u\n", fact);
    return 0;
}
