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

#ifndef __BBFDM_UCI_H
#define __BBFDM_UCI_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def bbfdm_section_name(s)
 * @brief Retrieves the name of a UCI section.
 * @param s Pointer to the UCI section.
 * @return Name of the section, or an empty string if the section is NULL.
 */
#define bbfdm_section_name(s) s ? (s)->e.name : ""

/**
 * @def bbfdm_section_type(s)
 * @brief Retrieves the type of a UCI section.
 * @param s Pointer to the UCI section.
 * @return Type of the section, or an empty string if the section is NULL.
 */
#define bbfdm_section_type(s) s ? (s)->type : ""

/**
 * @def bbfdm_section_config(s)
 * @brief Retrieves the configuration name of a UCI section.
 * @param s Pointer to the UCI section.
 * @return Name of the configuration, or an empty string if the section is NULL.
 */
#define bbfdm_section_config(s) s ? (s)->package->e.name : ""

/**
 * @brief Initializes the UCI context within the BBFDM context.
 *
 * Allocates and sets up the UCI context for use with BBFDM operations.
 *
 * @param[in,out] bbfdm_ctx Pointer to the BBFDM context structure.
 * @return 0 on success, -1 on failure.
 */
int bbfdm_init_uci_ctx(struct bbfdm_ctx *bbfdm_ctx);

/**
 * @brief Frees the UCI context within the BBFDM context.
 *
 * Releases resources associated with the UCI context.
 *
 * @param[in,out] bbfdm_ctx Pointer to the BBFDM context structure.
 * @return 0 on success, -1 on failure.
 */
int bbfdm_free_uci_ctx(struct bbfdm_ctx *bbfdm_ctx);

/**
 * @brief Retrieves a UCI option value into a buffer.
 *
 * Fetches the value of a specific option within a package and section, falling back to a default value if the option is not found.
 *
 * @param[in] bbfdm_ctx Pointer to the BBFDM context structure.
 * @param[in] package Name of the UCI package.
 * @param[in] section Name of the section within the package.
 * @param[in] option Name of the option within the section.
 * @param[in] default_value Default value to use if the option is not found.
 * @param[out] buffer Buffer to store the retrieved value.
 * @param[in] buffer_size Size of the buffer.
 * @return 0 on success, -1 on failure.
 */
int bbfdm_uci_get_buf(struct bbfdm_ctx *bbfdm_ctx, const char *package, const char *section, const char *option, const char *default_value,
		char *buffer, size_t buffer_size);

/**
 * @brief Retrieves a UCI option value as a dynamically allocated string.
 *
 * Fetches the value of a specific option within a package and section, returning it as a string allocated by the BBFDM memory system.
 *
 * @param[in] bbfdm_ctx Pointer to the BBFDM context structure.
 * @param[in] package Name of the UCI package.
 * @param[in] section Name of the section within the package.
 * @param[in] option Name of the option within the section.
 * @param[out] value Pointer to store the allocated string containing the option value.
 * @return 0 on success, -1 on failure.
 */
int bbfdm_uci_get(struct bbfdm_ctx *bbfdm_ctx, const char *package, const char *section, const char *option, char **value);

/**
 * @brief Retrieves a UCI option value with a fallback default.
 *
 * Fetches the value of a specific option within a package and section, falling back to the specified default value if the option is not found.
 *
 * @param[in] bbfdm_ctx Pointer to the BBFDM context structure.
 * @param[in] package Name of the UCI package.
 * @param[in] section Name of the section within the package.
 * @param[in] option Name of the option within the section.
 * @param[in] default_value Fallback default value if the option is not found.
 * @param[out] value Pointer to store the allocated string containing the option value.
 * @return 0 on success, -1 on failure.
 */
int bbfdm_uci_get_fallback_def(struct bbfdm_ctx *bbfdm_ctx, const char *package, const char *section, const char *option, const char *default_value, char **value);

/**
 * @brief Retrieves a UCI option value by section into a buffer.
 *
 * Searches for an option within a given section and stores the value in a buffer. If not found, a default value is used.
 *
 * @param[in] bbfdm_ctx Pointer to the BBFDM context structure.
 * @param[in] section Pointer to the UCI section.
 * @param[in] option Name of the option within the section.
 * @param[in] default_value Default value to use if the option is not found.
 * @param[out] buffer Buffer to store the retrieved value.
 * @param[in] buffer_size Size of the buffer.
 * @return 0 on success, -1 on failure.
 */
int bbfdm_uci_get_by_section_buf(struct bbfdm_ctx *bbfdm_ctx, struct uci_section *section, const char *option, const char *default_value,
		char *buffer, size_t buffer_size);

/**
 * @brief Retrieves a UCI option value by section as a dynamically allocated string.
 *
 * Searches for an option within a given section and returns the value as a dynamically allocated string.
 *
 * @param[in] bbfdm_ctx Pointer to the BBFDM context structure.
 * @param[in] section Pointer to the UCI section.
 * @param[in] option Name of the option within the section.
 * @param[out] value Pointer to store the allocated string containing the option value.
 * @return 0 on success, -1 on failure.
 */
int bbfdm_uci_get_by_section(struct bbfdm_ctx *bbfdm_ctx, struct uci_section *section, const char *option, char **value);

/**
 * @brief Sets a UCI option value.
 *
 * Updates the value of a specific option within a package and section.
 *
 * @param[in] bbfdm_ctx Pointer to the BBFDM context structure.
 * @param[in] package Name of the UCI package.
 * @param[in] section Name of the section within the package.
 * @param[in] option Name of the option within the section.
 * @param[in] value Value to set for the option.
 * @return 0 on success, -1 on failure.
 */
int bbfdm_uci_set(struct bbfdm_ctx *bbfdm_ctx, const char *package, const char *section, const char *option, const char *value);

/**
 * @brief Adds a new section to a UCI package.
 *
 * Creates a new section of the specified type within the given package.
 *
 * @param[in] bbfdm_ctx Pointer to the BBFDM context structure.
 * @param[in] package Name of the UCI package.
 * @param[in] type Type of the section to create.
 * @param[out] s Pointer to store the created section.
 * @return 0 on success, -1 on failure.
 */
int bbfdm_uci_add(struct bbfdm_ctx *bbfdm_ctx, const char *package, const char *type, struct uci_section **s);

/**
 * @brief Deletes a UCI option or section.
 *
 * Removes a specific option or an entire section from a UCI package.
 *
 * @param[in] bbfdm_ctx Pointer to the BBFDM context structure.
 * @param[in] package Name of the UCI package.
 * @param[in] section Name of the section within the package.
 * @param[in] option Name of the option to delete, or NULL to delete the section.
 * @return 0 on success, -1 on failure.
 */
int bbfdm_uci_delete(struct bbfdm_ctx *bbfdm_ctx, const char *package, const char *section, const char *option);

/**
 * @brief Deletes a UCI section.
 *
 * Removes a specific section from a UCI package.
 *
 * @param[in] bbfdm_ctx Pointer to the BBFDM context structure.
 * @param[in] s Pointer to the section to delete.
 * @return 0 on success, -1 on failure.
 */
int bbfdm_uci_delete_section(struct bbfdm_ctx *bbfdm_ctx, struct uci_section *s);

/**
 * @brief Commits changes to a UCI package.
 *
 * Saves all modifications made to a UCI package.
 *
 * @param[in] bbfdm_ctx Pointer to the BBFDM context structure.
 * @param[in] package Name of the UCI package.
 * @return 0 on success, -1 on failure.
 */
int bbfdm_uci_commit_package(struct bbfdm_ctx *bbfdm_ctx, const char *package);

/**
 * @brief Iterates over sections of a specific type in a UCI package.
 *
 * Traverses through all sections of the specified type within a package.
 *
 * @param[in] bbfdm_ctx Pointer to the BBFDM context structure.
 * @param[in] package Name of the UCI package.
 * @param[in] type Type of the sections to iterate.
 * @param[in] prev_section Pointer to the previous section, or NULL to start from the first section.
 * @return Pointer to the next section, or NULL if no more sections are found.
 */
struct uci_section *bbfdm_uci_walk_section(struct bbfdm_ctx *bbfdm_ctx, const char *package, const char *type, struct uci_section *prev_section);

/**
 * @brief Retrieves a value from the UCI configuration system.
 *
 * This macro simplifies the process of initializing a context, retrieving a UCI
 * configuration value, and cleaning up the context.
 *
 * @param package The name of the UCI package.
 * @param section The section name within the package.
 * @param option The option name within the section.
 * @param default_value Default value to use if the option is not found.
 * @param buffer Buffer to store the retrieved value.
 * @param buffer_size Size of the buffer.
 * @return Always returns 0.
 */
#define BBFDM_UCI_GET(package, section, option, default_value, buffer, buffer_size) \
	do { \
		struct bbfdm_ctx ctx = {0}; \
		memset(&ctx, 0, sizeof(struct bbfdm_ctx)); \
		bbfdm_init_ctx(&ctx); \
		bbfdm_uci_get_buf(&ctx, package, section, option, default_value, buffer, buffer_size); \
		bbfdm_free_ctx(&ctx); \
	} while (0)

/**
 * @brief Sets a value in the UCI configuration system.
 *
 * This macro simplifies the process of initializing a context, setting a UCI
 * configuration value, committing the changes, and cleaning up the context.
 *
 * @param package The name of the UCI package.
 * @param section The section name within the package.
 * @param option The option name within the section.
 * @param value The value to set for the specified option.
 * @return Always returns 0.
 */
#define BBFDM_UCI_SET(package, section, option, value) \
	do { \
		struct bbfdm_ctx ctx = {0}; \
		memset(&ctx, 0, sizeof(struct bbfdm_ctx)); \
		bbfdm_init_ctx(&ctx); \
		bbfdm_uci_set(&ctx, package, section, option, value); \
		bbfdm_uci_commit_package(&ctx, package); \
		bbfdm_free_ctx(&ctx); \
	} while (0)

/**
 * @brief Iterates over all sections of a specific type in a UCI package.
 *
 * This macro provides a convenient way to traverse all sections of a given type
 * within a specified UCI package. It uses the `bbfdm_uci_walk_section` function
 * to retrieve each section one by one.
 *
 * @param bbfdm_ctx Pointer to the bbfdm context.
 * @param package Name of the UCI package to iterate over.
 * @param type Type of the sections to filter during iteration.
 * @param section Variable to hold the current section being processed during the loop.
 *
 * @note This macro modifies the value of the `section` variable during iteration.
 * Ensure `section` is properly declared before using the macro.
 *
 * Example usage:
 * @code
 * const char *section;
 * BBFDM_UCI_FOREACH_SECTION(&ctx, "network", "interface", section) {
 *     printf("Processing section: %s\n", section);
 * }
 * @endcode
 */
#define BBFDM_UCI_FOREACH_SECTION(bbfdm_ctx, package, type, section) \
	for (section = bbfdm_uci_walk_section(bbfdm_ctx, package, type, NULL); \
		section != NULL; \
		section = bbfdm_uci_walk_section(bbfdm_ctx, package, type, section))

/**
 * @brief Safely iterates over all sections of a specific type in a UCI package.
 *
 * This macro provides a safe way to traverse all sections of a given type within
 * a specified UCI package. It ensures that the loop remains valid even if the
 * current section is modified or deleted during the iteration.
 *
 * @param bbfdm_ctx Pointer to the bbfdm context.
 * @param package Name of the UCI package to iterate over.
 * @param type Type of the sections to filter during iteration.
 * @param _tmp Temporary variable to store the next section during iteration. Must be declared beforehand.
 * @param section Variable to hold the current section being processed during the loop.
 *
 * @note Both `_tmp` and `section` variables are modified during iteration.
 * Ensure they are properly declared before using the macro.
 *
 * Example usage:
 * @code
 * const char *section, *next_section;
 * BBFDM_UCI_FOREACH_SECTION_SAFE(&ctx, "network", "interface", next_section, section) {
 *     printf("Processing section: %s\n", section);
 * }
 * @endcode
 */
#define BBFDM_UCI_FOREACH_SECTION_SAFE(bbfdm_ctx, package, type, _tmp, section)		\
	for(section = bbfdm_uci_walk_section(bbfdm_ctx, package, type, NULL), \
		_tmp = (section) ? bbfdm_uci_walk_section(bbfdm_ctx, package, type, section) : NULL;	\
		section != NULL; \
		section = _tmp, _tmp = (section) ? bbfdm_uci_walk_section(bbfdm_ctx, package, type, section) : NULL)

#ifdef __cplusplus
}
#endif

#endif //__BBFDM_UCI_H

