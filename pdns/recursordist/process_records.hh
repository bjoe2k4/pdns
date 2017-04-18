/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#pragma once

#include "dnsname.hh"
#include "qtype.hh"
#include "lwres.hh"
#include "dns.hh"
#include "negcache.hh"

/*
 * process_records.{cc,hh} implements the algorithms to process return packets
 * from authoritative servers. It has one entrypoint (processRecords()) that calls
 * all other functions required.
 */

int processCNAMEs(const LWResult& lwr, const DNSName& qname, const QType& qtype, const DNSName& auth, vector<DNSRecord>& ret, DNSName &newtarget);
int processReferral(const LWResult& lwr, const DNSName& qname, const DNSName& auth, DNSName& newauth, set<DNSName>& nsset);
int processNxDomain(const LWResult& lwr, const DNSName& qname, const QType& qtype, const DNSName& auth, NegCache::NegCacheEntry& ne);
int processRecords(const LWResult& lwr, const DNSName& qname, const QType& qtype, const DNSName& auth, vector<DNSRecord>& ret, DNSName& newtarget, NegCache::NegCacheEntry& ne, DNSName& newauth, set<DNSName>& nsset);
