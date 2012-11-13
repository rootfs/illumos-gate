/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

#ifndef	_SYS_ZAP_H
#define	_SYS_ZAP_H

/**
 * \file zap.h
 * \brief ZAP - ZFS Attribute Processor
 *
 * The ZAP is a module which sits on top of the DMU (Data Management
 * Unit) and implements a higher-level storage primitive using DMU
 * objects.  Its primary consumer is the ZPL (ZFS Posix Layer).
 *
 * A "zapobj" is a DMU object which the ZAP uses to stores attributes.
 * Users should use only zap routines to access a zapobj - they should
 * not access the DMU object directly using DMU routines.
 *
 * The attributes stored in a zapobj are name-value pairs.  The name is
 * a zero-terminated string of up to ZAP_MAXNAMELEN bytes (including
 * terminating NULL).  The value is an array of integers, which may be
 * 1, 2, 4, or 8 bytes long.  The total space used by the array (number
 * of integers * integer length) can be up to ZAP_MAXVALUELEN bytes.
 * Note that an 8-byte integer value can be used to store the location
 * (object number) of another dmu object (which may be itself a zapobj).
 * Note that you can use a zero-length attribute to store a single bit
 * of information - the attribute is present or not.
 *
 * The ZAP routines are thread-safe.  However, you must observe the
 * DMU's restriction that a transaction may not be operated on
 * concurrently.
 *
 * Any of the routines that return an int may return an I/O error (EIO
 * or ECHECKSUM).
 *
 *
 * <H2>Implementation / Performance Notes</H2>
 *
 * The ZAP is intended to operate most efficiently on attributes with
 * short (49 bytes or less) names and single 8-byte values, for which
 * the microzap will be used.  The ZAP should be efficient enough so
 * that the user does not need to cache these attributes.
 *
 * The ZAP's locking scheme makes its routines thread-safe.  Operations
 * on different zapobjs will be processed concurrently.  Operations on
 * the same zapobj which only read data will be processed concurrently.
 * Operations on the same zapobj which modify data will be processed
 * concurrently when there are many attributes in the zapobj (because
 * the ZAP uses per-block locking - more than 128 * (number of cpus)
 * small attributes will suffice).
 */

/*
 * We're using zero-terminated byte strings (ie. ASCII or UTF-8 C
 * strings) for the names of attributes, rather than a byte string
 * bounded by an explicit length.  If some day we want to support names
 * in character sets which have embedded zeros (eg. UTF-16, UTF-32),
 * we'll have to add routines for using length-bounded strings.
 */

#include <sys/dmu.h>

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * \brief Specifies which entry will be accessed.
 *
 * - <b>MT_EXACT</b>: only find an exact match (non-normalized)
 * - <b>MT_FIRST</b>: find the "first" normalized (case and Unicode
 *     form) match; the designated "first" match will not change as long
 *     as the set of entries with this normalization doesn't change
 * - <b>MT_BEST</b>: if there is an exact match, find that, otherwise find the
 *     first normalized match
 */
typedef enum matchtype
{
	MT_EXACT,
	MT_BEST,
	MT_FIRST
} matchtype_t;

typedef enum zap_flags {
	/**
	 * Use 64-bit hash value (serialized cursors will always use 64-bits)
	 */
	ZAP_FLAG_HASH64 = 1 << 0,
	/** Key is binary, not string (zap_add_uint64() can be used) */
	ZAP_FLAG_UINT64_KEY = 1 << 1,
	/**
	 * First word of key (which must be an array of uint64) is
	 * already randomly distributed.
	 */
	ZAP_FLAG_PRE_HASHED_KEY = 1 << 2,
} zap_flags_t;

uint64_t zap_create(objset_t *ds, dmu_object_type_t ot,
    dmu_object_type_t bonustype, int bonuslen, dmu_tx_t *tx);
uint64_t zap_create_norm(objset_t *ds, int normflags, dmu_object_type_t ot,
    dmu_object_type_t bonustype, int bonuslen, dmu_tx_t *tx);
uint64_t zap_create_flags(objset_t *os, int normflags, zap_flags_t flags,
    dmu_object_type_t ot, int leaf_blockshift, int indirect_blockshift,
    dmu_object_type_t bonustype, int bonuslen, dmu_tx_t *tx);
uint64_t zap_create_link(objset_t *os, dmu_object_type_t ot,
    uint64_t parent_obj, const char *name, dmu_tx_t *tx);

int zap_create_claim(objset_t *ds, uint64_t obj, dmu_object_type_t ot,
    dmu_object_type_t bonustype, int bonuslen, dmu_tx_t *tx);
int zap_create_claim_norm(objset_t *ds, uint64_t obj,
    int normflags, dmu_object_type_t ot,
    dmu_object_type_t bonustype, int bonuslen, dmu_tx_t *tx);

/*
 * The zapobj passed in must be a valid ZAP object for all of the
 * following routines.
 */

int zap_destroy(objset_t *ds, uint64_t zapobj, dmu_tx_t *tx);

/*
 * Manipulate attributes.
 *
 * 'integer_size' is in bytes, and must be 1, 2, 4, or 8.
 */

int zap_lookup(objset_t *ds, uint64_t zapobj, const char *name,
    uint64_t integer_size, uint64_t num_integers, void *buf);
int zap_lookup_norm(objset_t *ds, uint64_t zapobj, const char *name,
    uint64_t integer_size, uint64_t num_integers, void *buf,
    matchtype_t mt, char *realname, int rn_len,
    boolean_t *normalization_conflictp);
int zap_lookup_uint64(objset_t *os, uint64_t zapobj, const uint64_t *key,
    int key_numints, uint64_t integer_size, uint64_t num_integers, void *buf);
int zap_contains(objset_t *ds, uint64_t zapobj, const char *name);
int zap_prefetch_uint64(objset_t *os, uint64_t zapobj, const uint64_t *key,
    int key_numints);

int zap_count_write(objset_t *os, uint64_t zapobj, const char *name,
    int add, uint64_t *towrite, uint64_t *tooverwrite);

int zap_add(objset_t *ds, uint64_t zapobj, const char *key,
    int integer_size, uint64_t num_integers,
    const void *val, dmu_tx_t *tx);
int zap_add_uint64(objset_t *ds, uint64_t zapobj, const uint64_t *key,
    int key_numints, int integer_size, uint64_t num_integers,
    const void *val, dmu_tx_t *tx);

int zap_update(objset_t *ds, uint64_t zapobj, const char *name,
    int integer_size, uint64_t num_integers, const void *val, dmu_tx_t *tx);
int zap_update_uint64(objset_t *os, uint64_t zapobj, const uint64_t *key,
    int key_numints,
    int integer_size, uint64_t num_integers, const void *val, dmu_tx_t *tx);

int zap_length(objset_t *ds, uint64_t zapobj, const char *name,
    uint64_t *integer_size, uint64_t *num_integers);
int zap_length_uint64(objset_t *os, uint64_t zapobj, const uint64_t *key,
    int key_numints, uint64_t *integer_size, uint64_t *num_integers);

int zap_remove(objset_t *ds, uint64_t zapobj, const char *name, dmu_tx_t *tx);
int zap_remove_norm(objset_t *ds, uint64_t zapobj, const char *name,
    matchtype_t mt, dmu_tx_t *tx);
int zap_remove_uint64(objset_t *os, uint64_t zapobj, const uint64_t *key,
    int key_numints, dmu_tx_t *tx);

int zap_count(objset_t *ds, uint64_t zapobj, uint64_t *count);

int zap_value_search(objset_t *os, uint64_t zapobj,
    uint64_t value, uint64_t mask, char *name);

int zap_join(objset_t *os, uint64_t fromobj, uint64_t intoobj, dmu_tx_t *tx);

int zap_join_key(objset_t *os, uint64_t fromobj, uint64_t intoobj,
    uint64_t value, dmu_tx_t *tx);

int zap_join_increment(objset_t *os, uint64_t fromobj, uint64_t intoobj,
    dmu_tx_t *tx);

int zap_add_int(objset_t *os, uint64_t obj, uint64_t value, dmu_tx_t *tx);
int zap_remove_int(objset_t *os, uint64_t obj, uint64_t value, dmu_tx_t *tx);
int zap_lookup_int(objset_t *os, uint64_t obj, uint64_t value);
int zap_increment_int(objset_t *os, uint64_t obj, uint64_t key, int64_t delta,
    dmu_tx_t *tx);

int zap_add_int_key(objset_t *os, uint64_t obj,
    uint64_t key, uint64_t value, dmu_tx_t *tx);
int zap_update_int_key(objset_t *os, uint64_t obj,
    uint64_t key, uint64_t value, dmu_tx_t *tx);
int zap_lookup_int_key(objset_t *os, uint64_t obj,
    uint64_t key, uint64_t *valuep);

int zap_increment(objset_t *os, uint64_t obj, const char *name, int64_t delta,
    dmu_tx_t *tx);

struct zap;
struct zap_leaf;
typedef struct zap_cursor {
	/* This structure is opaque! */
	objset_t *zc_objset;
	struct zap *zc_zap;
	struct zap_leaf *zc_leaf;
	uint64_t zc_zapobj;
	uint64_t zc_serialized;
	uint64_t zc_hash;
	uint32_t zc_cd;
} zap_cursor_t;

typedef struct {
	int za_integer_length;
	/**
	 * za_normalization_conflict will be set if there are additional
	 * entries with this normalized form (eg, "foo" and "Foo").
	 */
	boolean_t za_normalization_conflict;
	uint64_t za_num_integers;
	uint64_t za_first_integer;/**< no sign extension for <8byte ints */
	char za_name[MAXNAMELEN];
} zap_attribute_t;

/*
 * The interface for listing all the attributes of a zapobj can be
 * thought of as cursor moving down a list of the attributes one by
 * one.  The cookie returned by the zap_cursor_serialize routine is
 * persistent across system calls (and across reboot, even).
 */

void zap_cursor_init(zap_cursor_t *zc, objset_t *ds, uint64_t zapobj);
void zap_cursor_fini(zap_cursor_t *zc);

int zap_cursor_retrieve(zap_cursor_t *zc, zap_attribute_t *za);

void zap_cursor_advance(zap_cursor_t *zc);

uint64_t zap_cursor_serialize(zap_cursor_t *zc);

/*
 * Advance the cursor to the attribute having the given key.
 */
int zap_cursor_move_to_key(zap_cursor_t *zc, const char *name, matchtype_t mt);

/*
 * Initialize a zap cursor pointing to the position recorded by
 * zap_cursor_serialize (in the "serialized" argument).  You can also
 * use a "serialized" argument of 0 to start at the beginning of the
 * zapobj (ie.  zap_cursor_init_serialized(..., 0) is equivalent to
 * zap_cursor_init(...).)
 */
void zap_cursor_init_serialized(zap_cursor_t *zc, objset_t *ds,
    uint64_t zapobj, uint64_t serialized);


#define	ZAP_HISTOGRAM_SIZE 10

typedef struct zap_stats {
	/**
	 * Size of the pointer table (in number of entries).
	 * This is always a power of 2, or zero if it's a microzap.
	 * In general, it should be considerably greater than zs_num_leafs.
	 */
	uint64_t zs_ptrtbl_len;

	uint64_t zs_blocksize;		/**< size of zap blocks */

	/**
	 * The number of blocks used.  Note that some blocks may be
	 * wasted because old ptrtbl's and large name/value blocks are
	 * not reused.  (Although their space is reclaimed, we don't
	 * reuse those offsets in the object.)
	 */
	uint64_t zs_num_blocks;

	/**
	 * \name Pointer table values from zap_ptrtbl in the zap_phys_t
	 * \{
	 */
	uint64_t zs_ptrtbl_nextblk;	  /**< next (larger) copy start block */
	uint64_t zs_ptrtbl_blks_copied;   /**< number source blocks copied */
	uint64_t zs_ptrtbl_zt_blk;	  /**< starting block number */
	uint64_t zs_ptrtbl_zt_numblks;    /**< number of blocks */
	uint64_t zs_ptrtbl_zt_shift;	  /**< bits to index it */
	/** \} */

	/**
	 * \name Values of the other members of the zap_phys_t
	 * \{
	 */
	uint64_t zs_block_type;		/**< ZBT_HEADER */
	uint64_t zs_magic;		/**< ZAP_MAGIC */
	uint64_t zs_num_leafs;		/**< The number of leaf blocks */
	uint64_t zs_num_entries;	/**< The number of zap entries */
	uint64_t zs_salt;		/**< salt to stir into hash function */
	/** \} */

	/**
	 * \name Histograms
	 *
	 * For all histograms, the last index (ZAP_HISTOGRAM_SIZE-1) includes
	 * any values which are greater than what can be represented.  For
	 * example zs_leafs_with_n5_entries[ZAP_HISTOGRAM_SIZE-1] is the number
	 * of leafs with more than 45 entries.
	 * \{
	 */

	/**
	 * zs_leafs_with_n_pointers[n] is the number of leafs with
	 * 2^n pointers to it.
	 */
	uint64_t zs_leafs_with_2n_pointers[ZAP_HISTOGRAM_SIZE];

	/**
	 * zs_leafs_with_n_entries[n] is the number of leafs with
	 * [n*5, (n+1)*5) entries.  In the current implementation, there
	 * can be at most 55 entries in any block, but there may be
	 * fewer if the name or value is large, or the block is not
	 * completely full.
	 */
	uint64_t zs_blocks_with_n5_entries[ZAP_HISTOGRAM_SIZE];

	/**
	 * zs_leafs_n_tenths_full[n] is the number of leafs whose
	 * fullness is in the range [n/10, (n+1)/10).
	 */
	uint64_t zs_blocks_n_tenths_full[ZAP_HISTOGRAM_SIZE];

	/**
	 * zs_entries_using_n_chunks[n] is the number of entries which
	 * consume n 24-byte chunks.  (Note, large names/values only use
	 * one chunk, but contribute to zs_num_blocks_large.)
	 */
	uint64_t zs_entries_using_n_chunks[ZAP_HISTOGRAM_SIZE];

	/**
	 * zs_buckets_with_n_entries[n] is the number of buckets (each
	 * leaf has 64 buckets) with n entries.
	 * zs_buckets_with_n_entries[1] should be very close to
	 * zs_num_entries.
	 */
	uint64_t zs_buckets_with_n_entries[ZAP_HISTOGRAM_SIZE];
	/** \} */
} zap_stats_t;

int zap_get_stats(objset_t *ds, uint64_t zapobj, zap_stats_t *zs);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZAP_H */
