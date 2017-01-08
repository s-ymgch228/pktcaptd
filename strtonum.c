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
