#pragma once

#include "dnsparser.hh"
#include "dnsname.hh"
#include <vector>
#include "namespaces.hh"
#include "dnsrecords.hh"
#include "vstate.hh"

extern bool g_dnssecLOG;

// NSEC(3) results
enum dState { NODATA, NXDOMAIN, ENT, INSECURE };
extern const char *dStates[];


class DNSRecordOracle
{
public:
  virtual std::vector<DNSRecord> get(const DNSName& qname, uint16_t qtype)=0;
};


struct ContentSigPair
{
  vector<shared_ptr<DNSRecordContent>> records;
  vector<shared_ptr<RRSIGRecordContent>> signatures;
  // ponder adding a validate method that accepts a key
};
typedef map<pair<DNSName,uint16_t>, ContentSigPair> cspmap_t;
typedef std::set<DSRecordContent> dsmap_t;
void validateWithKeySet(const cspmap_t& rrsets, cspmap_t& validated, const std::set<DNSKEYRecordContent>& keys);
cspmap_t harvestCSPFromRecs(const vector<DNSRecord>& recs);
vState getKeysFor(DNSRecordOracle& dro, const DNSName& zone, std::set<DNSKEYRecordContent> &keyset);

