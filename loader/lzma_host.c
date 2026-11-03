#include "lzma_dec.h"

#include <stdio.h>
#include <stdlib.h>

static unsigned char *load(const char *path, size_t *size)
{
    FILE *file = fopen(path, "rb");
    if (!file || fseek(file, 0, SEEK_END))
        return NULL;
    long end = ftell(file);
    if (end < 0 || fseek(file, 0, SEEK_SET))
        return NULL;
    unsigned char *data = malloc((size_t)end ? (size_t)end : 1);
    if (!data || fread(data, 1, (size_t)end, file) != (size_t)end) {
        free(data);
        return NULL;
    }
    fclose(file);
    *size = (size_t)end;
    return data;
}

int main(int argc, char **argv)
{
    if (argc != 4)
        return 2;
    size_t input_size = 0;
    unsigned char *input = load(argv[1], &input_size);
    size_t output_size = strtoul(argv[2], NULL, 0);
    unsigned char *output = malloc(output_size ? output_size : 1);
    unsigned int workspace_size = lzma_workspace_size();
    void *workspace = malloc(workspace_size);
    if (!input || !output || !workspace)
        return 3;
    int result = lzma_decode(output, output_size, input, input_size,
                             workspace, workspace_size);
    if (result)
        return 10 + result;
    FILE *file = fopen(argv[3], "wb");
    if (!file || fwrite(output, 1, output_size, file) != output_size)
        return 4;
    fclose(file);
    free(workspace);
    free(output);
    free(input);
    return 0;
}
