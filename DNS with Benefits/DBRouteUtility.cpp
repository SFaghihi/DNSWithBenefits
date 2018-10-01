//
//  DBRouteUtility.c
//  DNS with Benefits
//
//  Created by Soroush Faghihi on 8/19/18.
//  Copyright © 2018 sorco. All rights reserved.
//

/*
 * Copyright (c) 2008-2013 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * Copyright (c) 1983, 1989, 1991, 1993
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by the University of
 *    California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "DBRouteUtility.h"

#include <sys/cdefs.h>

#ifndef lint
__unused static const char copyright[] =
"@(#) Copyright (c) 1983, 1989, 1991, 1993\n\
The Regents of the University of California.  All rights reserved.\n";
#endif /* not lint */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <ifaddrs.h>

#define ROUNDUP(a) \
((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

static const char *msgtypes[] = {
    "",
    "RTM_ADD: Add Route",
    "RTM_DELETE: Delete Route",
    "RTM_CHANGE: Change Metrics or flags",
    "RTM_GET: Report Metrics",
    "RTM_LOSING: Kernel Suspects Partitioning",
    "RTM_REDIRECT: Told to use different route",
    "RTM_MISS: Lookup failed on this address",
    "RTM_LOCK: fix specified metrics",
    "RTM_OLDADD: caused by SIOCADDRT",
    "RTM_OLDDEL: caused by SIOCDELRT",
    "RTM_RESOLVE: Route created by cloning",
    "RTM_NEWADDR: address being added to iface",
    "RTM_DELADDR: address being removed from iface",
    "RTM_IFINFO: iface status change",
    "RTM_NEWMADDR: new multicast group membership on iface",
    "RTM_DELMADDR: multicast group membership removed from iface",
    0,
};

static u_char metricnames[] =
"\011pksent\010rttvar\7rtt\6ssthresh\5sendpipe\4recvpipe\3expire\2hopcount"
"\1mtu";
static u_char routeflags[] =
"\1UP\2GATEWAY\3HOST\4REJECT\5DYNAMIC\6MODIFIED\7DONE\010DELCLONE"
"\011CLONING\012XRESOLVE\013LLINFO\014STATIC\015BLACKHOLE\016b016"
"\017PROTO2\020PROTO1\021PRCLONING\022WASCLONED\023PROTO3\024b024"
"\025PINNED\026LOCAL\027BROADCAST\030MULTICAST\031IFSCOPE\032CONDEMNED"
"\033IFREF\034PROXY\035ROUTER";
static u_char ifnetflags[] =
"\1UP\2BROADCAST\3DEBUG\4LOOPBACK\5PTP\6b6\7RUNNING\010NOARP"
"\011PPROMISC\012ALLMULTI\013OACTIVE\014SIMPLEX\015LINK0\016LINK1"
"\017LINK2\020MULTICAST";
static u_char addrnames[] =
"\1DST\2GATEWAY\3NETMASK\4GENMASK\5IFP\6IFA\7AUTHOR\010BRD";

const char *routename(struct sockaddr *sa, int nflag)
{
    char *cp;
    static char line[MAXHOSTNAMELEN + 1];
    struct hostent *hp;
    static char domain[MAXHOSTNAMELEN + 1];
    static int first = 1;
    
    if (first) {
        first = 0;
        if (gethostname(domain, MAXHOSTNAMELEN) == 0 &&
            (cp = index(domain, '.'))) {
            domain[MAXHOSTNAMELEN] = '\0';
            (void) memmove(domain, cp + 1, strlen(cp + 1) + 1);
        } else
            domain[0] = 0;
    }
    
    if (sa->sa_len == 0)
        strlcpy(line, "default", sizeof(line));
    else switch (sa->sa_family) {
            
        case AF_INET:
        {    struct in_addr in;
            in = ((struct sockaddr_in *)sa)->sin_addr;
            
            cp = 0;
            if (in.s_addr == INADDR_ANY || sa->sa_len < 4)
                strncpy(cp, "default", strlen("default"));
            if (cp == 0 && !nflag) {
                hp = gethostbyaddr((char *)&in, sizeof (struct in_addr),
                                   AF_INET);
                if (hp) {
                    if ((cp = index(hp->h_name, '.')) &&
                        !strcmp(cp + 1, domain))
                        *cp = 0;
                    cp = hp->h_name;
                }
            }
            if (cp) {
                strncpy(line, cp, sizeof(line) - 1);
                line[sizeof(line) - 1] = '\0';
            } else {
                /* XXX - why not inet_ntoa()? */
#define C(x)    (unsigned)((x) & 0xff)
                in.s_addr = ntohl(in.s_addr);
                (void) snprintf(line, sizeof(line), "%u.%u.%u.%u", C(in.s_addr >> 24),
                                C(in.s_addr >> 16), C(in.s_addr >> 8), C(in.s_addr));
            }
            break;
        }
            
#ifdef INET6
        case AF_INET6:
        {
            struct sockaddr_in6 sin6; /* use static var for safety */
            int niflags = 0;
#ifdef NI_WITHSCOPEID
            niflags = NI_WITHSCOPEID;
#endif
            
            memset(&sin6, 0, sizeof(sin6));
            memcpy(&sin6, sa, sa->sa_len);
            sin6.sin6_len = sizeof(struct sockaddr_in6);
            sin6.sin6_family = AF_INET6;
#ifdef __KAME__
            if (sa->sa_len == sizeof(struct sockaddr_in6) &&
                (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr) ||
                 IN6_IS_ADDR_MC_NODELOCAL(&sin6.sin6_addr) ||
                 IN6_IS_ADDR_MC_LINKLOCAL(&sin6.sin6_addr)) &&
                sin6.sin6_scope_id == 0) {
                sin6.sin6_scope_id =
                ntohs(*(u_int16_t *)&sin6.sin6_addr.s6_addr[2]);
                sin6.sin6_addr.s6_addr[2] = 0;
                sin6.sin6_addr.s6_addr[3] = 0;
            }
#endif
            if (nflag)
                niflags |= NI_NUMERICHOST;
            if (getnameinfo((struct sockaddr *)&sin6, sin6.sin6_len,
                            line, sizeof(line), NULL, 0, niflags) != 0)
                strncpy(line, "invalid", sizeof(line));
            
            return(line);
        }
#endif
            
        case AF_LINK:
            return (link_ntoa((struct sockaddr_dl *)sa));
            
        default:
        {    u_short *s = (u_short *)sa;
            u_short *slim = s + ((sa->sa_len + 1) >> 1);
            char *cp = line + snprintf(line, sizeof(line), "(%d)", sa->sa_family);
            char *cpe = line + sizeof(line);
            
            while (++s < slim && cp < cpe) /* start with sa->sa_data */
                cp += snprintf(cp, cpe - cp, " %x", *s);
            break;
        }
    }
    return (line);
}


void bprintf(FILE *fp, int b, u_char *s)
{
    int i;
    int gotsome = 0;
    
    if (b == 0)
        return;
    while ((i = *s++) != 0)
    {
        if (b & (1 << (i-1)))
        {
            if (gotsome == 0)
                i = '<';
            else
                i = ',';
            (void) putc(i, fp);
            gotsome = 1;
            for (; (i = *s) > 32; s++)
                (void) putc(i, fp);
        }
        else
            while (*s > 32)
                s++;
    }
    if (gotsome)
        (void) putc('>', fp);
}

void pmsg_addrs(char *cp, int addrs, int nflag)
{
    struct sockaddr *sa;
    int i;
    
    if (addrs == 0)
    {
        (void) putchar('\n');
        return;
    }
    (void) printf("\nsockaddrs: ");
    bprintf(stdout, addrs, addrnames);
    (void) putchar('\n');
    for (i = 1; i; i <<= 1)
        if (i & addrs)
        {
            sa = (struct sockaddr *)cp;
            (void) printf(" %s", routename(sa, nflag));
            ADVANCE(cp, sa);
        }
    (void) putchar('\n');
    (void) fflush(stdout);
}

void pmsg_common(struct rt_msghdr *rtm, int nflag)
{
    (void) printf("\nlocks: ");
    bprintf(stdout, rtm->rtm_rmx.rmx_locks, metricnames);
    (void) printf(" inits: ");
    bprintf(stdout, rtm->rtm_inits, metricnames);
    pmsg_addrs(((char *)(rtm + 1)), rtm->rtm_addrs, nflag);
}

void print_rtmsg(struct rt_msghdr *rtm, int nflag)
{
    struct if_msghdr *ifm;
    struct ifa_msghdr *ifam;
#ifdef RTM_NEWMADDR
    struct ifma_msghdr *ifmam;
#endif
    
    if (rtm->rtm_version != RTM_VERSION)
    {
        (void) printf("routing message version %d not understood\n", rtm->rtm_version);
        return;
    }
    (void)printf("%s: len %d, ", msgtypes[rtm->rtm_type], rtm->rtm_msglen);
    switch (rtm->rtm_type)
    {
        case RTM_IFINFO:
            ifm = (struct if_msghdr *)rtm;
            (void) printf("if# %d, flags:", ifm->ifm_index);
            bprintf(stdout, ifm->ifm_flags, ifnetflags);
            pmsg_addrs((char *)(ifm + 1), ifm->ifm_addrs, nflag);
            break;
            
        case RTM_NEWADDR:
        case RTM_DELADDR:
            ifam = (struct ifa_msghdr *)rtm;
            (void) printf("metric %d, flags:", ifam->ifam_metric);
            bprintf(stdout, ifam->ifam_flags, routeflags);
            pmsg_addrs((char *)(ifam + 1), ifam->ifam_addrs, nflag);
            break;
            
#ifdef RTM_NEWMADDR
        case RTM_NEWMADDR:
        case RTM_DELMADDR:
            ifmam = (struct ifma_msghdr *)rtm;
            pmsg_addrs((char *)(ifmam + 1), ifmam->ifmam_addrs, nflag);
            break;
#endif
            
        default:
            (void) printf("pid: %ld, seq %d, errno %d, ", (long)rtm->rtm_pid, rtm->rtm_seq, rtm->rtm_errno);
            if (rtm->rtm_flags & RTF_IFSCOPE)
                (void) printf("ifscope %d, ", rtm->rtm_index);
            if (rtm->rtm_flags & RTF_IFREF)
                (void) printf("ifref, ");
            (void) printf("flags:");
            bprintf(stdout, rtm->rtm_flags, routeflags);
            pmsg_common(rtm, nflag);
    }
}

void interfaces(int nflag)
{
    size_t needed;
    int mib[6];
    char *buf, *lim, *next;
    struct rt_msghdr *rtm;
    
    mib[0] = CTL_NET;
    mib[1] = PF_ROUTE;
    mib[2] = 0;        /* protocol */
    mib[3] = 0;        /* wildcard address family */
    mib[4] = NET_RT_IFLIST;
    mib[5] = 0;        /* no flags */
    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
        perror("route-sysctl-estimate");
    if ((buf = (char *)malloc(needed)) == NULL)
        perror("malloc failed");
    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0)
        perror("actual retrieval of interface table");
    lim = buf + needed;
    for (next = buf; next < lim; next += rtm->rtm_msglen)
    {
        rtm = (struct rt_msghdr *)next;
        print_rtmsg(rtm, nflag);
    }
}
