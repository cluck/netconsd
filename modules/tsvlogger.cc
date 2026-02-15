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
	char logfname[INET6_ADDRSTRLEN + 9];  /* .tsv.log */
	int fd;
	char tss[TSS_SIZE];
	char kv[KV_SIZE];

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
		strncpy(p, ".tsv.log", 8);

		ret = open(logfname, O_WRONLY|O_APPEND|O_CREAT, 0644);
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

/*
 * Actually write the line to the file
 */
static void write_log(struct logtarget& tgt, struct msg_buf *buf,
		struct ncrx_msg *msg)
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

	/* extended netcons msg with metadata */
	const char *version = (msg->version != 0 && std::strlen(msg->version) > 0) ? msg->version : "0.0.0";

	char *drd = msg->dict;
	char *dwr = tgt.kv;
	size_t wfree = KV_SIZE-1;
	char *drdnx;
	*dwr = '\0';
	drdnx = drd;
	while (drdnx != 0 && *drdnx != 0 && wfree > 0)
	{
		while (    (drdnx = strchr(drdnx, '\n')) != 0
			&& !(drdnx[1] == ' ' || drdnx[1] == '\0'))
				drdnx++;
		size_t ll = drdnx - drd - 1;  /* skip the initial space */
		if (ll > 0 && ll <= wfree)
		{
			memcpy(dwr, drd+1, ll < wfree ? ll : wfree);
			wfree -= ll;
			dwr += ll;
			strncpy(dwr++, ";", wfree--);
		}
		drd = ++drdnx;
	}
	tgt.kv[KV_SIZE] = '\0';

	dprintf(tgt.fd, "%s\t%" PRIu64 "\t%014" PRIu64 "\t%d\t%d\t%s%s%s%s\t%s\t%s\t%s%s\n",
		tgt.tss,
		msg->seq,
		msg->ts_usec,
		msg->facility,
		msg->level,
		msg->cont_start ? "[CONT START]" : "",
		msg->cont       ? "[CONT]"       : "",
		msg->oos        ? "[OOS]"        : "",
		msg->seq_reset  ? "[SEQ RESET]"  : "",
		version,
		msg->text,
		tgt.kv[0]       ? "\t" : "",
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
