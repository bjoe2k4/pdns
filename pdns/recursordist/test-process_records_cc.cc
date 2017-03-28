#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>
#include "test-functions.hh"
#include "process_records.hh"

BOOST_AUTO_TEST_SUITE(process_records_cc_processNXDomain)
BOOST_AUTO_TEST_CASE(test_nxdomain_normal) {
  /* A normal NXDomain response. Nothing in the answer section and a SOA in AUTHORITY */
  DNSName qname("www.example.com");
  DNSName auth("example.com");
  QType qtype = QType(1);
  vector<DNSRecord> ret;
  NegCacheEntry ne;

  LWResult lwr;
  setLWResult(&lwr, RCode::NXDomain, true, false, false);
  addRecordToLW(&lwr, auth, QType::SOA, "ns1.example.com hostmaster.example.com 1 2 3 4 5", DNSResourceRecord::AUTHORITY);

  int res = processNxDomain(lwr, qname, qtype, auth, ret, ne);

  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret[0].d_place, DNSResourceRecord::AUTHORITY);
  BOOST_CHECK_EQUAL(ret[0].d_name, auth);
  BOOST_CHECK_EQUAL(ret[0].d_type, QType::SOA);
  BOOST_CHECK_EQUAL(ne.d_name, qname);
  BOOST_CHECK_EQUAL(ne.d_qname, auth);
  BOOST_CHECK_EQUAL(ne.d_qtype.getCode(), QType::ENT);
}

BOOST_AUTO_TEST_SUITE_END()

// Tests for processCNAMEs
BOOST_AUTO_TEST_SUITE(process_records_cc_processCNAMEs)
/* A response with a 2 stage CNAME chain
 *  www.example.net -> www2.example.net -> www.example.com
 *
 *  Order in packet:
 *  www.example.net CNAME www2.example.net
 *  www2.example.net CNAME www.example.com
 */
BOOST_AUTO_TEST_CASE(test_processCNAME) {
  DNSName auth("example.com");
  DNSName newtarget;
  QType qtype = QType(1);
  vector<DNSRecord> ret;

  LWResult lwr;
  setLWResult(&lwr, RCode::NoError, true, false, false);
  addRecordToLW(&lwr, "www.example.com", QType::CNAME, "www2.example.com");
  addRecordToLW(&lwr, "www2.example.com", QType::CNAME, "www.example.net");

  int res = processCNAMEs(lwr, DNSName("www.example.com"), qtype, auth, ret, newtarget);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(newtarget, DNSName("www.example.net"));
}

/* A response with an out of order chain.
 *  www.example.net -> www2.example.net -> www.example.com
 *
 *  Order in packet:
 *  www2.example.net CNAME www.example.com
 *  www.example.net CNAME www2.example.net
 */
BOOST_AUTO_TEST_CASE(test_processCNAME_outoforder) {
  DNSName auth("example.com");
  DNSName newtarget;
  QType qtype = QType(1);
  vector<DNSRecord> ret;

  LWResult lwr;
  setLWResult(&lwr, RCode::NoError, true, false, false);
  addRecordToLW(&lwr, "www2.example.com", QType::CNAME, "www.example.net");
  addRecordToLW(&lwr, "www.example.com", QType::CNAME, "www2.example.com");

  int res = processCNAMEs(lwr, DNSName("www.example.com"), qtype, auth, ret, newtarget);

  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(newtarget, DNSName("www.example.net"));
  BOOST_CHECK_EQUAL(ret.size(), 2);
}

/* A response without any CNAMEs
 */
BOOST_AUTO_TEST_CASE(test_processCNAME_nocnames) {
  DNSName qname("www.example.com");
  QType qtype = QType(1);
  DNSName newtarget;
  DNSName auth("example.com");
  vector<DNSRecord> ret;

  LWResult lwr;
  setLWResult(&lwr, RCode::NoError, true, false, false);
  addRecordToLW(&lwr, qname, QType::A, "192.0.2.1");

  int res = processCNAMEs(lwr, qname, qtype, auth, ret, newtarget);

  BOOST_CHECK_EQUAL(res, 1);
  BOOST_CHECK_EQUAL(newtarget, DNSName());
  BOOST_CHECK_EQUAL(ret.size(), 0);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(process_records_cc_processReferral)
/* A normal referral from com to example.com
 */
BOOST_AUTO_TEST_CASE(test_referral) {
  DNSName qname("www.example.com");
  DNSName nsname("example.com");
  DNSName auth("com");
  DNSName newauth;
  set<DNSName> nsset;

  LWResult lwr;
  setLWResult(&lwr, 0, true, false, true);
  addRecordToLW(&lwr, nsname, QType::NS, "ns1.example.com", DNSResourceRecord::AUTHORITY, 3600);
  addRecordToLW(&lwr, nsname, QType::NS, "ns2.example.com", DNSResourceRecord::AUTHORITY, 3600);

  int res = processReferral(lwr, qname, auth, newauth, nsset);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(nsset.size(), 2);
  BOOST_CHECK_EQUAL(newauth, nsname);
}

BOOST_AUTO_TEST_CASE(test_referral_skipLevel) {
  DNSName qname("www.sub.example.com");
  DNSName nsname("sub.example.com");
  DNSName auth("com");
  DNSName newauth;
  set<DNSName> nsset;

  LWResult lwr;
  setLWResult(&lwr, 0, true, false, true);
  addRecordToLW(&lwr, nsname, QType::NS, "ns1.example.com", DNSResourceRecord::AUTHORITY, 3600);
  addRecordToLW(&lwr, nsname, QType::NS, "ns2.example.com", DNSResourceRecord::AUTHORITY, 3600);

  int res = processReferral(lwr, qname, auth, newauth, nsset);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(nsset.size(), 2);
  BOOST_CHECK_EQUAL(newauth, nsname);
}

/* An upward referral from 'com' to '.' should be rejected
 */
BOOST_AUTO_TEST_CASE(test_referral_upward) {
  DNSName qname("www.example.com");
  DNSName nsname(".");
  DNSName auth("com");
  DNSName newauth;
  set<DNSName> nsset;

  LWResult lwr;
  setLWResult(&lwr, 0, true, false, true);
  addRecordToLW(&lwr, nsname, QType::NS, "ns1.example.com", DNSResourceRecord::AUTHORITY, 3600);
  addRecordToLW(&lwr, nsname, QType::NS, "ns2.example.com", DNSResourceRecord::AUTHORITY, 3600);

  int res = processReferral(lwr, qname, auth, newauth, nsset);
  BOOST_CHECK_EQUAL(res, -1);
  BOOST_CHECK_EQUAL(nsset.size(), 0);
  BOOST_CHECK_EQUAL(newauth, DNSName());
}

BOOST_AUTO_TEST_SUITE_END()
