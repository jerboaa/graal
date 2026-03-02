#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bfd.h>
#include <zlib.h>

typedef union {
  unsigned char c[8];
  uint64_t l;
} char_to_uint64_t;

#ifdef DEBUG

#define LOG_DEBUG(format, type, param)   \
{                                        \
   fprintf(stderr, format, (type)param); \
}

#else

#define LOG_DEBUG(format, type, param)

#endif

static asymbol **read_symbols(bfd *abfd, long *symcount) {
    long storage_needed;
    asymbol **symbol_table;

    storage_needed = bfd_get_dynamic_symtab_upper_bound(abfd);
    if (storage_needed < 0) {
        fprintf(stderr, "Failed to get dynamic symbol table size\n");
        return NULL;
    }

    if (storage_needed == 0) {
        fprintf(stderr, "No dynamic symbols found\n");
        return NULL;
    }

    symbol_table = (asymbol **) malloc(storage_needed);
    if (!symbol_table) {
        fprintf(stderr, "Failed to allocate memory for symbol table\n");
        return NULL;
    }

    *symcount = bfd_canonicalize_dynamic_symtab(abfd, symbol_table);
    if (*symcount < 0) {
        free(symbol_table);
        fprintf(stderr, "Failed to read dynamic symbols\n");
        return NULL;
    }

    return symbol_table;
}

static asymbol *find_symbol(asymbol **symbol_table, long symcount, const char *name) {
    for (long i = 0; i < symcount; i++) {
        if (symbol_table[i]->name && strcmp(symbol_table[i]->name, name) == 0) {
            return symbol_table[i];
        }
    }
    return NULL;
}

static int extract_compressed_data(bfd *abfd, asymbol* sbom_sym, uint64_t* sbom_size, bfd_vma offset, unsigned char** data) {
    asection *section = sbom_sym->section;

    if (!section) {
        fprintf(stderr, "Symbol has no associated section\n");
        return 1;
    }

    bfd_size_type sec_size = bfd_section_size(section);
    if (offset >= sec_size) {
        fprintf(stderr, "Symbol offset out of section bounds\n");
        return 1;
    }

    *data = malloc(*sbom_size);

    if (!*data) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }

    if (!bfd_get_section_contents(abfd, section, *data, offset, *sbom_size)) {
        fprintf(stderr, "Failed to read section contents\n");
        free(*data);
        *data = NULL;
        return 1;
    }

    return 0;
}

static int read_number(bfd *abfd, asymbol *sym, uint64_t *data) {
    asection *section = sym->section;

    if (!section) {
        fprintf(stderr, "Symbol has no associated section\n");
        return 1;
    }

    bfd_size_type sec_size = bfd_section_size(section);
    bfd_vma sym_value = bfd_asymbol_value(sym);
    bfd_vma section_vma = bfd_section_vma(section);

    // Calculate offset within section
    bfd_vma offset = sym_value - section_vma;

    if (offset >= sec_size) {
        fprintf(stderr, "Symbol offset out of section bounds\n");
        return 1;
    }

    unsigned char num_data[8];

    // read the 8 bytes of the size value
    if (!bfd_get_section_contents(abfd, section, num_data, offset, 8)) {
        fprintf(stderr, "Failed to read section contents\n");
        return 1;
    }
    // convert bytes to int64_t
    char_to_uint64_t t;
    t.c[0] = num_data[0];
    t.c[1] = num_data[1];
    t.c[2] = num_data[2];
    t.c[3] = num_data[3];
    t.c[4] = num_data[4];
    t.c[5] = num_data[5];
    t.c[6] = num_data[6];
    t.c[7] = num_data[7];

    *data = t.l;

    return 0;
}

#define CHUNK_SIZE 16384

// inflate data in 'source' with len 'source_len' to the buffer pointed to by
// 'dest'. The output length will be set in 'dest_len'.
static int inflate_gzip(const unsigned char *source, uint64_t source_len,
                        unsigned char **dest, uint64_t *dest_len) {
    z_stream strm;
    int ret;
    size_t output_size = 0;
    size_t output_capacity = CHUNK_SIZE;
    unsigned char *output = malloc(output_capacity);
    unsigned char out_buffer[CHUNK_SIZE];

    if (!output) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }

    // Initialize zlib stream
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;

    // Initialize for gzip format (windowBits = 15 + 16 for gzip)
    ret = inflateInit2(&strm, 15 + 16);
    if (ret != Z_OK) {
        fprintf(stderr, "Failed to initialize zlib: %d\n", ret);
        free(output);
        return 1;
    }

    // Set input
    strm.avail_in = source_len;
    strm.next_in = (unsigned char *)source;

    // Decompress until end of stream
    do {
        strm.avail_out = CHUNK_SIZE;
        strm.next_out = out_buffer;

        ret = inflate(&strm, Z_NO_FLUSH);

        switch (ret) {
            case Z_NEED_DICT:
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                fprintf(stderr, "Decompression error: %d\n", ret);
                inflateEnd(&strm);
                free(output);
                return 1;
        }

        size_t have = CHUNK_SIZE - strm.avail_out;

        // Resize output buffer if needed
        if (output_size + have > output_capacity) {
            output_capacity *= 2;
            unsigned char *new_output = realloc(output, output_capacity);
            if (!new_output) {
                fprintf(stderr, "Failed to reallocate memory\n");
                inflateEnd(&strm);
                free(output);
                return 1;
            }
            output = new_output;
        }

        // Copy decompressed data to output
        memcpy(output + output_size, out_buffer, have);
        output_size += have;

    } while (strm.avail_out == 0);

    // Cleanup
    inflateEnd(&strm);

    if (ret != Z_STREAM_END) {
        fprintf(stderr, "Incomplete decompression\n");
        free(output);
        return 1;
    }

    *dest = output;
    *dest_len = output_size;

    return 0;
}

#undef CHUNK_SIZE

// Retrieves an embedded SBOM (gzip compressed) from a binary (executable or
// shared library). The executable parameter is the path to the binary. The
// SBOM is streamed to stdout
int extract_sbom(const char* executable) {
    bfd *abfd;
    asymbol **symbol_table;
    asymbol *sbom_sym, *sbom_size_sym;
    long symcount;
    bfd_vma sbom_addr;

    // Initialize BFD library
    bfd_init();

    // Open the ELF file
    abfd = bfd_openr(executable, NULL);
    if (!abfd) {
        fprintf(stderr, "Failed to open file '%s': %s\n", executable, bfd_errmsg(bfd_get_error()));
        return 1;
    }

    // Check format
    if (!bfd_check_format(abfd, bfd_object)) {
        fprintf(stderr, "File '%s' is not an object file: %s\n", executable, bfd_errmsg(bfd_get_error()));
        bfd_close(abfd);
        return 1;
    }

    // Read dynamic symbols
    symbol_table = read_symbols(abfd, &symcount);
    if (symbol_table == NULL) {
        bfd_close(abfd);
        return 1;
    }

    // Find the 'sbom' symbol
    sbom_sym = find_symbol(symbol_table, symcount, "sbom");
    if (sbom_sym == NULL) {
        fprintf(stderr, "Symbol 'sbom' not found in dynamic symbol table\n");
        free(symbol_table);
        bfd_close(abfd);
        return 1;
    }

    // Find the 'sbom_length' symbol
    sbom_size_sym = find_symbol(symbol_table, symcount, "sbom_length");
    if (sbom_size_sym == NULL) {
        fprintf(stderr, "Symbol 'sbom_length' not found in dynamic symbol table\n");
        free(symbol_table);
        bfd_close(abfd);
        return 1;
    }

    // Get the addresses
    sbom_addr = bfd_asymbol_value(sbom_sym);

    // Determine the number of bytes we need to read from 'sbom'
    uint64_t sbom_size = 0;
    if (read_number(abfd, sbom_size_sym, &sbom_size) != 0) {
        fprintf(stderr, "Failed to read sbom_size value\n");
        return 1;
    }
    bfd_vma offset = sbom_addr - bfd_section_vma(sbom_sym->section);

    LOG_DEBUG("sbom address: 0x%lx\n", unsigned long, sbom_addr);
    LOG_DEBUG("sbom_length: %lu bytes\n", unsigned long, sbom_size);
    unsigned char *data = NULL;

    // Extract the compressed data
    if (extract_compressed_data(abfd, sbom_sym, &sbom_size, offset, &data) != 0) {
        free(symbol_table);
        bfd_close(abfd);
        return 1;
    }

    // Decompress the data
    uint64_t decompressed_len = 0;
    unsigned char *decompressed_data = NULL;
    if (inflate_gzip(data, sbom_size, &decompressed_data, &decompressed_len) != 0) {
        fprintf(stderr, "Failed to decompress data\n");
        free(data);
        return 1;
    }
    fwrite(decompressed_data, decompressed_len, 1, stdout);

    LOG_DEBUG("Successfully extracted %lu bytes of compressed data\n", unsigned long, sbom_size);

    // Cleanup
    free(decompressed_data);
    free(symbol_table);
    bfd_close(abfd);
    return 0;
}

