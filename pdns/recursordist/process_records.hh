#pragma once

#include "dnsname.hh"
#include "qtype.hh"
#include "lwres.hh"
#include "dns.hh"
#include "syncres.hh"

#define processInvalidResponse -2
#define processWasWrongRCode -1
#define processWasValid 0
#define processWasCNAME 1
#define processWasReferral 2

int processCNAMEs(const LWResult& lwr, const DNSName& qname, const QType& qtype, const DNSName& auth, vector<DNSRecord>& ret, DNSName &newtarget);
int processReferral(const LWResult& lwr, const DNSName& qname, const DNSName& auth, DNSName& newauth, set<DNSName>& nsset);
int processNxDomain(const LWResult& lwr, const DNSName& qname, const QType& qtype, const DNSName& auth, DNSRecord& rec, NegCacheEntry& ne);
