/*
 * Copyright (C) 2025 iopsys Software Solutions AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 *	  Author: Amin Ben Romdhane <amin.benromdhane@iopsys.eu>
 *
 */

#ifndef __BBFDM_MEM_H
#define __BBFDM_MEM_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initializes the memory management list for the bbfdm context.
 *
 * This function allocates and initializes a memory list head within the given
 * bbfdm context. This list is used to manage dynamic memory allocations.
 *
 * @param bbfdm_ctx Pointer to the bbfdm context.
 *
 * @note This function must be called before using any other memory-related functions.
 * Ensure to free the memory by calling `bbfdm_free_mem()` when done.
 */
void bbfdm_init_mem(struct bbfdm_ctx *bbfdm_ctx);

/**
 * @brief Frees all dynamically allocated memory in the bbfdm context.
 *
 * This function traverses the memory list and frees all dynamically allocated
 * memory blocks, as well as the list head itself.
 *
 * @param bbfdm_ctx Pointer to the bbfdm context.
 *
 * @note Ensure that all allocated memory in the context is no longer in use
 * before calling this function.
 */
void bbfdm_free_mem(struct bbfdm_ctx *bbfdm_ctx);

/**
 * @brief Allocates a block of memory and tracks it in the bbfdm context.
 *
 * This function allocates a block of memory of the specified size and adds it
 * to the memory management list in the bbfdm context.
 *
 * @param bbfdm_ctx Pointer to the bbfdm context.
 * @param size Size of the memory block to allocate.
 * @return Pointer to the allocated memory block, or NULL on failure.
 */
void *bbfdm_malloc(struct bbfdm_ctx *bbfdm_ctx, size_t size);

/**
 * @brief Allocates and zero-initializes a block of memory and tracks it in the bbfdm context.
 *
 * This function allocates a block of memory for an array of `n` elements of
 * `size` bytes each and initializes all bytes to zero. The allocation is
 * tracked in the memory management list in the bbfdm context.
 *
 * @param bbfdm_ctx Pointer to the bbfdm context.
 * @param n Number of elements to allocate.
 * @param size Size of each element in bytes.
 * @return Pointer to the allocated and zero-initialized memory block, or NULL on failure.
 */
void *bbfdm_calloc(struct bbfdm_ctx *bbfdm_ctx, int n, size_t size);

/**
 * @brief Reallocates a previously allocated memory block to a new size.
 *
 * This function adjusts the size of a previously allocated memory block and
 * updates the memory management list in the bbfdm context. If the reallocation
 * fails, the original memory block is freed.
 *
 * @param bbfdm_ctx Pointer to the bbfdm context.
 * @param n Pointer to the existing memory block.
 * @param size New size of the memory block in bytes.
 * @return Pointer to the reallocated memory block, or NULL on failure.
 */
void *bbfdm_realloc(struct bbfdm_ctx *bbfdm_ctx, void *n, size_t size);

/**
 * @brief Duplicates a string and tracks it in the bbfdm context.
 *
 * This function allocates memory for a copy of the given string and adds it to
 * the memory management list in the bbfdm context.
 *
 * @param bbfdm_ctx Pointer to the bbfdm context.
 * @param s String to duplicate.
 * @return Pointer to the duplicated string, or NULL on failure.
 */
char *bbfdm_strdup(struct bbfdm_ctx *bbfdm_ctx, const char *s);

/**
 * @brief Formats a string and allocates memory for it in the bbfdm context.
 *
 * This function formats a string according to the given format specifier and
 * stores the result in a newly allocated memory block, tracked in the bbfdm
 * context.
 *
 * @param bbfdm_ctx Pointer to the bbfdm context.
 * @param s Pointer to a char pointer where the formatted string will be stored.
 * @param format Format specifier (similar to printf).
 * @param ... Additional arguments for the format specifier.
 * @return 0 on success, or -1 on failure.
 */
int bbfdm_asprintf(struct bbfdm_ctx *bbfdm_ctx, char **s, const char *format, ...);

/**
 * @brief Frees a specific memory block from the bbfdm context's memory list.
 *
 * This function removes a specific memory block from the memory management list
 * and frees its associated memory.
 *
 * @param m Pointer to the memory block to free.
 *
 * @note This function does not require the bbfdm context as it determines the
 * list entry from the given memory block pointer.
 */
void bbfdm_free_mem_bloc(const void *m);

#ifdef __cplusplus
}
#endif

#endif //__BBFDM_MEM_H

