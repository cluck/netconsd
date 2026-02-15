/* logger.cc: Very simple example C++ netconsd module
 *
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <unordered_map>
#include <inttypes.h>
#include <ctime>

#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <msgbuf-struct.h>
#include <ncrx-struct.h>

#include <jhash.h>

#define TSS_SIZE 200
#define KV_SIZE 8192
/* JSON worst case every character c becomes \uABCD (6 chars) */
#define JSMSG_SIZE 3+6*1000     /* netconsole line max 1000 chars */
#define JSK_SIZE 3+6*53         /* netconsole key maxlen 53 (2 quotes plus 6x53 plus final \0 is 321) */
#define JSV_SIZE 3+6*200        /* netconsole value maxlen 200 (2 quotes plus 6x200 plus final \0 is 1203) */
#define JSKNLV_SIZE 1024        /* Kernel version (max size?) */

/*
 * The below allows us to index an unordered_map by an IP address.
 */

static bool operator==(const struct in6_addr& lhs, const struct in6_addr& rhs)
{
	return std::memcmp(&lhs, &rhs, 16) == 0;
}

namespace std {

template<> struct hash<struct in6_addr>
{
	std::size_t operator()(struct in6_addr const& s) const
	{
		return jhash2((uint32_t*)&s, sizeof(s) / sizeof(uint32_t),
				0xbeefdead);
	}
};

} /* namespace std */

/*
 * Basic struct to hold the hostname and the FD for its logfile.
 */
struct logtarget {
	char hostname[INET6_ADDRSTRLEN + 1];
	char logfname[INET6_ADDRSTRLEN + 8];  /* .js.log */
	int fd;
	char tss[TSS_SIZE];
	char kv[KV_SIZE];
	char jsmsg[JSMSG_SIZE];
	char jsk[JSK_SIZE];
	char jsv[JSV_SIZE];
	char jsknlv[JSV_SIZE];

	/*
	 * Resolve the hostname, and open() an appropriately named file to
	 * write the logs into.
	 */
	logtarget(struct in6_addr *src)
	{
		int ret;
		struct sockaddr_in6 sa = {
			.sin6_family = AF_INET6,
			.sin6_port = 0,
		};

		memcpy(&sa.sin6_addr, src, sizeof(*src));
		ret = getnameinfo((const struct sockaddr *)&sa, sizeof(sa),
				hostname, sizeof(hostname) - 1, NULL, 0, NI_NAMEREQD);
		if (ret) {
			const char *ptr;
			fprintf(stderr, "getnameinfo failed: %s\n", gai_strerror(ret));
			ptr = inet_ntop(AF_INET6, src, hostname, INET6_ADDRSTRLEN);
			if (ptr == NULL) {
				fprintf(stderr, "inet_ntop failed: %s\n", strerror(errno));
				snprintf(hostname, 8, "unknown");
			}
		}
		size_t i = strncmp("::ffff:", hostname, 7)==0 ? 7 : 0;
		char *p = stpncpy(logfname, hostname+i, INET6_ADDRSTRLEN);
		strncpy(p, ".js.log", 7);

		ret = open(logfname, O_APPEND | O_WRONLY | O_CREAT, 0644);
		if (ret == -1) {
			fprintf(stderr, "FATAL: open() failed: %m\n");
			abort();
		}

		fd = ret;
	}

	/*
	 * Close the file
	 */
	~logtarget(void)
	{
		close(fd);
	}
};

/*
 * This relates the IP address of the remote host to its logtarget struct.
 */
static std::unordered_map<struct in6_addr, struct logtarget> *maps;

/*
 * Return the existing logtarget struct if we've seen this host before; else,
 * initialize a new logtarget, insert it, and return that.
 */
static struct logtarget& get_target(int thread_nr, struct in6_addr *src)
{
	auto itr = maps[thread_nr].find(*src);
	if (itr == maps[thread_nr].end())
		return maps[thread_nr].emplace(*src, src).first->second;

	return itr->second;
}

size_t json_escape_string(
	const char *input,
	char * const output,
	size_t input_maxlen,
	size_t output_maxlen
)
{
	size_t ret = 0;
	char *p = output;
	char *z = output + output_maxlen;
	unsigned char c;

	if (!input || !output || output_maxlen < 3 || input_maxlen < 0)
		goto err;

	*p++ = '"';
	for (size_t i = 0; input_maxlen >= 0 && i < input_maxlen && input[i] != '\0'; i++)
	{
		c = (unsigned char)input[i];
		if (c == '\0')
			break;
		if (p + 2 >= z)
			goto err;
		switch (c) {
		case '\"': strcpy(p, "\\\""); p += 2; break;
		case '\\': strcpy(p, "\\\\"); p += 2; break;
		case '\b': strcpy(p, "\\b"); p += 2; break;
		case '\f': strcpy(p, "\\f"); p += 2; break;
		case '\n': strcpy(p, "\\n"); p += 2; break;
		case '\r': strcpy(p, "\\r"); p += 2; break;
		case '\t': strcpy(p, "\\t"); p += 2; break;
		default:
			if (c >= 0x20)
				*p++ = c;
			else
			{
				if (p + 6 >= z)
					goto err;
				sprintf(p, "\\u%04x", c);
				p += 6;
			}
			break;
		}
	}
	if (p + 1 >= z)
		goto err;
	*p++ = '"';
	*p = '\0';

	ret = p - output;
	return ret;

err:
	if (output && output_maxlen > 0)
		output[0] = '\0';
	return ret;
}

/*
 * Actually write the line to the file
 */
static void write_log(
	struct logtarget& tgt,
	struct msg_buf *buf,
	struct ncrx_msg *msg
)
{
	time_t calndtm = msg->rx_at_real / 1000;    /* [msec], also have msg->rx_at_mono */
	struct tm *localtm;
	if (((localtm = localtime(&calndtm)) == 0) || (strftime(tgt.tss, TSS_SIZE, "%Y%m%dT%H%M%S%z", localtm) == 0))
		strncpy(tgt.tss, "0", TSS_SIZE);

	/* legacy non-extended netcons message */
	if (!msg) {
		dprintf(tgt.fd, "%s %s\n", tgt.tss, buf->buf);
		return;
	}

	size_t firstseen = 0;
	char *drd = msg->dict;
	char *dwr = tgt.kv + 6;
	size_t wfree = KV_SIZE - 8;  /* minus: '"kv":{' and '}\0' */
	char *drdnx = drd;
	char *drdsep;
	size_t kl;  /* key len */
	size_t vl;  /* value len */
	size_t jkl; /* key len encoded as json */
	size_t jvl; /* value len encoded as json */
	while (drdnx != 0 && *drdnx != 0 && wfree > 0)
	{
		while (    (drdnx = strchr(drdnx, '\n')) != 0
			&& !(drdnx[1] == ' ' || drdnx[1] == '\0'))
				drdnx++;
		if ((drdsep = strchr(drd, '=')) != 0)
		{
			kl = drdsep - drd - 1;    /* minus initial space */
			vl = drdnx - drdsep - 1;  /* minus final newline */
			jkl = json_escape_string(drd+1, tgt.jsk, kl, JSK_SIZE);
			jvl = json_escape_string(drdsep+1, tgt.jsv, vl, JSV_SIZE);
			if (jkl != 0 && jvl != 0 && jkl+jvl+1+firstseen < wfree)
			{
				if (firstseen != 0)  { *dwr++ = ','; wfree--; }
				dwr = stpncpy(dwr, tgt.jsk, jkl+1);
				*dwr++ = ':'; wfree -= jkl+1;
				dwr = stpncpy(dwr, tgt.jsv, jvl+1);
				wfree -= jvl;
				firstseen = 1;
			}
		}
		drd = ++drdnx;
	}
	if (firstseen == 0)
		*tgt.kv = '\0';
	else
	{
		dwr = stpncpy(dwr, "}", 2);
		memcpy(tgt.kv, "\"kv\":{", 6);
	}

	if (json_escape_string(msg->text, tgt.jsmsg, -1, JSMSG_SIZE) == 0)
		return;


	/* extended netcons msg with metadata */
	if (std::strlen(msg->version) > 0)
	{
		json_escape_string(msg->version, tgt.jsknlv, -1, JSKNLV_SIZE);
		dprintf(tgt.fd, "{\"ts\":\"%s\",\"m\":%s,\"k\":%s,\"seq\":%" PRIu64 ",\"ut\":%014" PRIu64 ",\"f\":%d,\"l\":%d%s%s%s%s%s%s}\n",
			tgt.tss, tgt.jsmsg, tgt.jsknlv, msg->seq, msg->ts_usec, msg->facility, msg->level,
			msg->cont_start ? ",\"cont_start\":true" : "",
			msg->cont ? ",\"cont\":true" : "",
			msg->oos ? ",\"oos\":true" : "",
			msg->seq_reset ? ",\"seq_reset\":true" : "",
			tgt.kv[0]       ? "," : "",
			tgt.kv
		);
	}
	else
		dprintf(tgt.fd, "{\"ts\":\"%s\",\"m\":%s,\"seq\":%" PRIu64 ",\"ut\":%014" PRIu64 ",\"f\":%d,\"l\":%d%s%s%s%s%s%s}\n",
			tgt.tss, tgt.jsmsg,              msg->seq, msg->ts_usec, msg->facility, msg->level,
			msg->cont_start ? ",\"cont_start\":true" : "",
			msg->cont ? ",\"cont\":true" : "",
			msg->oos ? ",\"oos\":true" : "",
			msg->seq_reset ? ",\"seq_reset\":true" : "",
			tgt.kv[0]       ? "," : "",
			tgt.kv
		);
}

extern "C" int netconsd_output_init(int nr)
{
	maps = new std::unordered_map<struct in6_addr, struct logtarget>[nr];
	return 0;
}

extern "C" void netconsd_output_exit(void)
{
	delete[] maps;
}

/*
 * This is the actual function called by netconsd.
 */
extern "C" void netconsd_output_handler(int t, struct in6_addr *src,
		struct msg_buf *buf, struct ncrx_msg *msg)
{
	struct logtarget& cur = get_target(t, src);
	write_log(cur, buf, msg);
}
