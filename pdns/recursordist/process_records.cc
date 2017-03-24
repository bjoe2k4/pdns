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

static bool magicAddrMatch(const QType& query, const uint16_t& answer)
{
  if(query != QType::ADDR)
    return false;
  return answer == QType::A || answer == QType::AAAA;
}

int processAnswer(const LWResult& lwr, const DNSName& qname, const QType& qtype, const DNSName& auth, vector<DNSRecord>& ret) {
  if (lwr.d_rcode != RCode::NoError)
    return -2;

  bool hadAnswer = false;

  for (auto& record : lwr.d_records) {
    if (record.d_class != QClass::IN && record.d_type != QType::OPT)
      // A non-IN record that is not OPT
      continue;

    if (!record.d_name.isPartOf(auth))
      // Don't trust any data not part of auth
      continue;

    if (record.d_name == qname && record.d_place == DNSResourceRecord::ANSWER &&
        (record.d_type == qtype.getCode() ||
         (lwr.d_aabit && (qtype == QType::ANY || magicAddrMatch(qtype, record.d_type)))
        )
       )
    {
      ret.push_back(record);
      hadAnswer = true;
    }
  }

  if (hadAnswer)
    return 0;
  return -1;
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
     *  How can ther be a CNAME redirection on an NXDOMAIN?
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
int processNoERROR(const LWResult& lwr, const DNSName& qname, const QType& qtype, const DNSName& auth, vector<DNSRecord>& ret, DNSName& newtarget) {
  if (lwr.d_rcode != RCode::NoError)
    return -1;

  bool haveFinalAnswer = false;

  for (auto& record : lwr) {
    if (record.d_place == DNSResourceRecord::ANSWER) {
      if (record.d_name == qname && (record.d_type == qtype || record.d_type == QType::ANY)) {
        haveFinalAnswer = true;
        ret.push_back(record);
      }
    }
  }
}
*/

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
 * \param rec    A DNSRecord that will contain the SOA from the AUTHORITY if this was a good NXDomain response
 * \param ne     A NegCacheEntry that will be filled out if lwr was a good NXDomain response
 */
int processNxDomain(const LWResult& lwr, const DNSName& qname, const QType& qtype, const DNSName& auth, DNSRecord& rec, NegCacheEntry& ne) {
  if (lwr.d_rcode != RCode::NXDomain)
    return -1;

  bool gotSOA = false;

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
      ne.d_qname = record.d_name;
      ne.d_qtype = QType(0); // this encodes 'whole record'
      ne.d_dnssecProof = harvestRecords(lwr.d_records, {QType::NSEC, QType::NSEC3});
      rec = record;
      gotSOA = true;
    }
  }

  if (!gotSOA)
    return -1;

  return 0;
}
