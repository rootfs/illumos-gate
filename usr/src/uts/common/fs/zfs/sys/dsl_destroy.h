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
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

#ifndef	_SYS_DSL_DESTROY_H
#define	_SYS_DSL_DESTROY_H

#ifdef	__cplusplus
extern "C" {
#endif

struct nvlist;
struct dsl_dataset;
struct dmu_tx;

struct dmu_snapshots_destroy_arg;
typedef void (*dmu_snapshots_destroy_syncfunc_t)(
    struct dmu_snapshots_destroy_arg *, dsl_pool_t *, dsl_dataset_t *,
    const char *);
typedef void (*dmu_snapshots_destroy_cleanupfunc_t)(
    struct dmu_snapshots_destroy_arg *);

typedef struct dmu_snapshots_destroy_arg {
	int dsda_error;
	nvlist_t *dsda_snaps;
	nvlist_t *dsda_successful_snaps;
	boolean_t dsda_defer;
	nvlist_t *dsda_errlist;
	void *dsda_user_data;
	dmu_snapshots_destroy_syncfunc_t dsda_user_syncfunc;
	dmu_snapshots_destroy_cleanupfunc_t dsda_user_cleanupfunc;
} dmu_snapshots_destroy_arg_t;

struct dsl_destroy_head_arg;
typedef void (*dsl_destroy_head_syncfunc_t)(
    struct dsl_destroy_head_arg *, dsl_dataset_t *);
typedef void (*dsl_destroy_head_cleanupfunc_t)(
    struct dsl_destroy_head_arg *);
typedef struct dsl_destroy_head_arg {
	const char *ddha_name;
	int ddha_error;
	void *ddha_user_data;
	dsl_destroy_head_syncfunc_t ddha_user_syncfunc;
	dsl_destroy_head_cleanupfunc_t ddha_user_cleanupfunc;
} dsl_destroy_head_arg_t;

int dsl_destroy_snapshots_nvl(struct nvlist *snaps, boolean_t defer,
    struct nvlist *errlist);
int dsl_destroy_snapshot(const char *name, boolean_t defer);
int dsl_destroy_head(const char *name);
int dsl_destroy_head_check_impl(struct dsl_dataset *ds, int expected_holds);
void dsl_destroy_head_sync_impl(struct dsl_dataset *ds, struct dmu_tx *tx);
int dsl_destroy_inconsistent(const char *dsname, void *arg);
void dsl_destroy_snapshot_sync_impl(struct dsl_dataset *ds,
    boolean_t defer, struct dmu_tx *tx);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_DSL_DESTROY_H */
