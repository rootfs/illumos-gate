/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

/*	$OpenBSD: uidswap.h,v 1.9 2001/06/26 17:27:25 markus Exp $	*/

#ifndef	_UIDSWAP_H
#define	_UIDSWAP_H

#ifdef __cplusplus
extern "C" {
#endif

void	 temporarily_use_uid(struct passwd *);
void	 restore_uid(void);
void	 permanently_set_uid(struct passwd *, char *);

#ifdef __cplusplus
}
#endif

#endif /* _UIDSWAP_H */
