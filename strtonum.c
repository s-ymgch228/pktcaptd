/*
 * Copyright (c) 2017, Shoichi Yamaguchi
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#include "pktcaptd.h"
long long
strtonum(const char *nptr, long long minival, long long maxval,
    const char **errstr)
{
	long long	 num = 0, x;
	const char		*dummy;
	const char		**msg;
	char		*endptr = NULL;

	if (errstr)
		msg = errstr;
	else
		msg = &dummy;

	*msg = NULL;

	errno = 0;
	x = strtoll(nptr, &endptr, 0);
	if (*nptr == '\0') {
		*msg = "not a number";
		goto done;
	}

	if (*endptr != '\0') {
		*msg = "not a number";
		goto done;
	}

	if (errno == ERANGE) {
		if (x == LLONG_MAX)
			*msg = "too big number";
		else if (x == LLONG_MIN)
			*msg = "too min number";

		goto done;
	}

	if (maxval < x)
		*msg = "too big number";
	else if (minival > x)
		*msg = "too min number";
	else
		num = x;


done:

	return num;
}
