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
#include "process_records.hh"

// Copied from syncres.cc
static recsig_t harvestRecords(const vector<DNSRecord>& records, const set<uint16_t>& types)
{
  recsig_t ret;
  for(const auto& rec : records) {
    if(rec.d_type == QType::RRSIG) {
      auto rrs=getRR<RRSIGRecordContent>(rec);
      if(rrs && types.count(rrs->d_type))
        ret[make_pair(rec.d_name, rrs->d_type)].signatures.push_back(rec);
    }
    else if(types.count(rec.d_type))
      ret[make_pair(rec.d_name, rec.d_type)].records.push_back(rec);
  }
  return ret;
}

// idem
static bool magicAddrMatch(const QType& query, const uint16_t& answer)
{
  if(query != QType::ADDR)
    return false;
  return answer == QType::A || answer == QType::AAAA;
}

/*
 * Returns true is the current record should be rejected.
 *
 * \param record The record to check
 * \param auth The authoritative zone for this record
 */
static inline bool rejectRecord(const DNSRecord& record, const DNSName& auth) {
  return (
      record.d_class != QClass::IN || // Reject non-IN
      record.d_type == QType::OPT ||  // Reject OPT
      !record.d_name.isPartOf(auth)); // Reject out of bailiwick
}

/* Returns the new CNAME target for newtarget, or an empty DNSName if none is found in CNAMEs.
 * When a CNAME is found, rec contains the DNSRecord with this CNAME record
 *
 * \param newtarget   The name of the record we want a new target for
 * \param CNAMEs      A vector of DNSRecords where we'll look for newtarget
 * \param rec         If a DNSRecord if found in CNAMEs, this DNSRecord is set to it
 */
DNSName getNewTarget(const DNSName& newtarget, const vector<DNSRecord>& CNAMEs, DNSRecord& rec) {
  DNSName ret;
  for (auto record : CNAMEs) {
    if (record.d_name == newtarget) {
      rec = record;
      if (auto content = getRR<CNAMERecordContent>(record))
        ret = content->getTarget();
      break;
    }
  }
  return ret;
}

/* Processes all CNAMES in the ANSWER section
 *
 * Returns 0 if there is a CNAME(chain), newtarget is set to the penultimate target and ret contains all relevant records (in chain order)
 * Returns 1 if there is no CNAME(chain)
 * Returns -1 if the response is not NOERROR or NXDOMAIN
 * Returns -2 if there were in-baliwick CNAMEs but no chain could be created
 *
 * **Note**: If the qtype parameter is CNAME, 1 will be returned
 *
 * \param lwr        An LWResult from an authoritative
 * \param qname      The qname being chased
 * \param qtype      The qtype requested
 * \param auth       The authoritative zone (so out of bailiwick answers are filtered)
 * \param ret        A vector of DNSRecords that will contain the answers for the client
 * \param newtarget  Set when lwr is a CNAME redirection
 */
int processCNAMEs(const LWResult& lwr, const DNSName& qname, const QType& qtype, const DNSName& auth, vector<DNSRecord>& ret, DNSName &newtarget) {
  if (!(lwr.d_rcode == RCode::NoError || lwr.d_rcode == RCode::NXDomain))
    /*
     *  How can there be a CNAME redirection on an NXDOMAIN?
     *  If an auth has example.com and example.net as zones, www.example.com is a
     *  CNAME to www.example.net and www.example.net does not exist, the ANSWER will
     *  contain the CNAME and the SOA in the AUTHORITY will be for example.net. But
     *  as example.net is not part of example.com (our auth), we won't trust this
     *  answer as negative.
     */
    return -1;

  if (qtype == QType::CNAME)
    return 1;

  // set newtarget to empty
  newtarget = DNSName();
  vector<DNSRecord> CNAMEs;

  for (auto& record : lwr.d_records) {
    if (record.d_class != QClass::IN && record.d_type != QType::OPT)
      // A non-IN record that is not OPT
      continue;

    if (!record.d_name.isPartOf(auth))
      // Don't trust any data not part of auth
      continue;

    if (record.d_place == DNSResourceRecord::ANSWER &&
        record.d_type == QType::CNAME)
      CNAMEs.push_back(record);
  }

  if (CNAMEs.empty())
    return 1;

  DNSName tmp_newtarget = qname;
  DNSRecord rec;

  while (!tmp_newtarget.empty()) {
    tmp_newtarget = getNewTarget(tmp_newtarget, CNAMEs, rec);
    if (!tmp_newtarget.empty()) {
      ret.push_back(rec);
      newtarget = tmp_newtarget;
    }
  }

  if (newtarget.empty())
    return -2;

  return 0;
}

/*
 * Processes NOERROR responses
 *
 * TODO Does *NOT* deal with answers from forwarded queries.
 *
 * -3 == AA bit was not set.
 * -2 == wrong rcode
 * -1 == No answer data (and not NODATA)
 * 0 == Answer found, ret contains the answer
 * 1 == NODATA
 * 2 == No answer data, but not NODATA
 */
int processAnswer(const LWResult& lwr, const DNSName& qname, const QType& qtype, const DNSName& auth, vector<DNSRecord>& ret, NegCacheEntry& ne) {
  if (lwr.d_rcode != RCode::NoError)
    return -2;

  if (!lwr.d_aabit) // Not trusting non-AA data for answers
    return -3;

  bool haveAnswer = false;
  bool haveSOA = false;
  DNSRecord SOARecord;
  vector<DNSRecord> answers;

  for (auto& record : lwr.d_records) {
    if (rejectRecord(record, auth))
      continue;

    if (record.d_name == qname && record.d_place == DNSResourceRecord::ANSWER &&
        (record.d_type == qtype.getCode() || qtype == QType::ANY || magicAddrMatch(qtype, record.d_type))) {
      haveAnswer = true;
      answers.push_back(record);
      continue;
    }

    if (record.d_place == DNSResourceRecord::AUTHORITY &&
        record.d_type == QType::SOA &&
        qname.isPartOf(record.d_name)){
      haveSOA = true;
      ne.d_name = qname;
      ne.d_qname = record.d_name;
      ne.d_qtype = qtype;
      ne.d_dnssecProof = harvestRecords(lwr.d_records, {QType::NSEC, QType::NSEC3});
      SOARecord = record;
      continue;
    }
  }

  if (haveSOA && !haveAnswer) {
    ret.push_back(SOARecord);
    return 1;
  }

  if (haveAnswer && !haveSOA) {
    ret.insert(ret.end(), answers.begin(), answers.end());
    return 0;
  }

  if (!haveAnswer && !haveSOA)
    return 2;

  if (haveAnswer && haveSOA) // what?
    return -2;

  return -1;
}

/* -2 = unprocessable results
 * 0 = Final answers
 * 1 = NODATA
 * 2 = Referral
 * 3 = NXDomain
 * 4 = CNAME redirect
 */
int processRecords(const LWResult& lwr, const DNSName& qname, const QType& qtype, const DNSName& auth, vector<DNSRecord>& ret,
    DNSName& newtarget,
    NegCacheEntry& ne,
    DNSName& newauth, set<DNSName>& nsset) {
  if (!(lwr.d_rcode == RCode::NoError || lwr.d_rcode == RCode::NXDomain))
    return -2;

  // Set newtarget to qname, after processCNAME, we use newtarget for every other
  // function call
  newtarget = qname;
  bool hadCNAME = false;
  int retval;

  retval = processCNAMEs(lwr, qname, qtype, auth, ret, newtarget);
  if (retval < 0)
    return -2;

  if (retval == 0)
    hadCNAME = true;

  if (lwr.d_rcode == RCode::NoError) {
    if (lwr.d_aabit) {
      retval = processAnswer(lwr, newtarget, qtype, auth, ret, ne);
      if (retval < 0)
        return -2;
      if (retval < 0)
        return retval;
    }

    // No final answer, but did we have a CNAME?
    if (hadCNAME)
      return 4;

    // No CNAME, was this a referral?
    retval = processReferral(lwr, newtarget, auth, newauth, nsset);
    if (retval == 0)
      return 2;

    // A NOERROR response without a CNAME chain, answer or referral... we done
    return -2;
  }

  // NXDOMAIN
  if (lwr.d_aabit) {
    retval = processNxDomain(lwr, newtarget, qtype, auth, ret, ne);
    if (retval < 0)
      return -2;
    return 0;
  }

  return -2;
}

/* -2 == This was not a NOERROR response
 * -1 == an upward/sideways referral was received
 * 0 == Referral, nsset and newauth are filled properly
 * 1 == There was no referral in lwr
 */
int processReferral(const LWResult& lwr, const DNSName& qname, const DNSName& auth, DNSName& newauth, set<DNSName>& nsset) {
  if (lwr.d_rcode != RCode::NoError)
    return -2;

  bool goodReferral = false;
  bool badReferral = false;

  for (auto& record : lwr.d_records) {
    if (record.d_class != QClass::IN && record.d_type != QType::OPT)
      // A non-IN record that is not OPT
      continue;

    if (record.d_place == DNSResourceRecord::AUTHORITY &&
        record.d_type == QType::NS) {
      // We have an NS record!
      if(!qname.isPartOf(record.d_name) || !record.d_name.isPartOf(auth)) {
        // This is either out of bailiwick or not related to the qname.
        badReferral = true;
        continue;
      }
      if (record.d_name.countLabels() <= auth.countLabels()) {
        // A sideways referral :(
        badReferral = true;
        continue;
      }
      newauth = record.d_name;
      goodReferral = true;
      if (auto content =  getRR<NSRecordContent>(record))
        nsset.insert(content->getNS());
    }
  }

  if (goodReferral)
      return 0;
  if (badReferral)
    return -1;
  return 1;
}

/*
 * This function checks if this is a proper NXDomain.
 * It does *not* perform CNAME processing!
 *
 * Return values:
 * -2 == The rcode was not NXDOMAIN
 * -1 == This was not a proper NXDomain response
 * 0  == This was an NXDOMAIN response, rec contains the SOA record form the AUTHORITY and NegCacheEntry is filled
 *
 * \param lwr    The LWResult from a reply packet
 * \param qname  The qname we're looking for
 * \param qtype  The qtype we're looking for
 * \param auth   The authoritative zone we received lwr from
 * \param ret    A vector of DNSRecord where the SOA from the AUTHORITY section will be added
 * \param ne     A NegCacheEntry that will be filled out if lwr was a good NXDomain response
 */
int processNxDomain(const LWResult& lwr, const DNSName& qname, const QType& qtype, const DNSName& auth, vector<DNSRecord>& ret, NegCacheEntry& ne) {
  if (lwr.d_rcode != RCode::NXDomain)
    return -1;

  DNSRecord SOARecord;

  for (auto& record : lwr.d_records) {
    if (record.d_class != QClass::IN && record.d_type != QType::OPT)
      // A non-IN record that is not OPT
      continue;

    if (!record.d_name.isPartOf(auth))
      // Don't trust any data not part of auth
      continue;

    if (record.d_place == DNSResourceRecord::AUTHORITY &&
        record.d_type == QType::SOA &&
        qname.isPartOf(record.d_name)) {
      // TODO return processInvalidResponse when gotSOA is already true?
      ne.d_name = qname;
      ne.d_qname = record.d_name;
      ne.d_qtype = QType(0); // this encodes 'whole record'
      ne.d_dnssecProof = harvestRecords(lwr.d_records, {QType::NSEC, QType::NSEC3});
      SOARecord = record;
    }
  }

  if (SOARecord.d_type != QType::SOA)
    return -1;

  ret.push_back(SOARecord);
  return 0;
}
