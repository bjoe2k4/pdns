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

#include "dnsparser.hh"
#include "dnsname.hh"
#include <vector>
#include "namespaces.hh"
#include "dnsrecords.hh"
#include "dnsrecordoracle.hh"
#include "vstate.hh"
#include "syncres.hh"

extern bool g_dnssecLOG;

// NSEC(3) results
enum dState { NODATA, NXDOMAIN, NXQTYPE, ENT, INSECURE, OPTOUT};
extern const char *dStates[];

struct ContentSigPair
{
  vector<shared_ptr<DNSRecordContent>> records;
  vector<shared_ptr<RRSIGRecordContent>> signatures;
  // ponder adding a validate method that accepts a key
};
typedef map<pair<DNSName,uint16_t>, ContentSigPair> cspmap_t;

class DNSSECValidator
{
  bool trace;
  public:
    DNSSECValidator(const bool& trace=false);
    DNSSECValidator(DNSRecordOracle& recordOracle, const bool& trace=false);
    typedef std::set<DSRecordContent> dsmap_t;

    /* should become the enrtypoint */
    vState validateRecords(const vector<DNSRecord>& records);

  private:
    void validateWithKeySet(const cspmap_t& rrsets, cspmap_t& validated, const std::set<DNSKEYRecordContent>& keys);
    vState getKeysFor(const DNSName& zone, std::set<DNSKEYRecordContent> &keyset);

    // Required as input for validateWithKeyset (called by validateRecords in validate-recursor.cc)
    cspmap_t harvestCSPFromRecs(const vector<DNSRecord>& recs);
    typedef set<DNSKEYRecordContent> keyset_t;
    shared_ptr<DNSRecordOracle> recordOracle;
    vector<DNSKEYRecordContent> getByTag(const keyset_t& keys, uint16_t tag);
    dState getDenial(const cspmap_t &validrrsets, const DNSName& qname, const uint16_t& qtype);
    vector<DNSName> getZoneCuts(const DNSName& begin, const DNSName& end);

    /* Graphviz related */
    void dotEdge(DNSName zone, string type1, DNSName name1, string tag1, string type2, DNSName name2, string tag2, string color="");
    void dotNode(string type, DNSName name, string tag, string content);
    string dotName(string type, DNSName name, string tag);
    string dotEscape(string name);
};
