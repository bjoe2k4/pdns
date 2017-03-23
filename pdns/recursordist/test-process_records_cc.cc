#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>
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
  lwr.d_rcode = RCode::NXDomain;
  lwr.d_aabit = true;

  DNSRecord record;
  record.d_name = qname;
  record.d_type = qtype.getCode();
  record.d_place = DNSResourceRecord::QUESTION;
  lwr.d_records.push_back(record);

  record.d_name = DNSName("example.com");
  record.d_type = QType::SOA;
  record.d_place = DNSResourceRecord::AUTHORITY;
  SOARecordContent src("ns1.example.com hostmaster.example.com 1 2 3 4 5");
  record.d_content = std::make_shared<SOARecordContent>(src);
  lwr.d_records.push_back(record);

  DNSName ignore;

  int res = processNxDomain(lwr, qname, qtype, auth, ret, ignore, ne);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 1);
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
  DNSName qname("www.example.com");
  DNSName qname2("www2.example.com");
  DNSName qname3("www.example.net");
  DNSName auth("example.com");
  DNSName newtarget;
  QType qtype = QType(1);
  vector<DNSRecord> ret;

  LWResult lwr;
  lwr.d_rcode = RCode::NoError;
  lwr.d_aabit = true;

  DNSRecord record;
  record.d_name = qname;
  record.d_type = qtype.getCode();
  record.d_place = DNSResourceRecord::QUESTION;
  lwr.d_records.push_back(record);

  record.d_name = qname;
  record.d_type = QType::CNAME;
  record.d_place = DNSResourceRecord::ANSWER;
  CNAMERecordContent content(qname2);
  record.d_content = std::make_shared<CNAMERecordContent>(content);
  lwr.d_records.push_back(record);

  record.d_name = qname2;
  CNAMERecordContent content2(qname2);
  content2 = CNAMERecordContent(qname3);
  record.d_content = std::make_shared<CNAMERecordContent>(content2);
  lwr.d_records.push_back(record);

  int res = processCNAMEs(lwr, qname, qtype, auth, ret, newtarget);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(ret.size(), 2);
  BOOST_CHECK_EQUAL(newtarget, qname3);
}

/* A response with an out of order chain.
 *  www.example.net -> www2.example.net -> www.example.com
 *
 *  Order in packet:
 *  www2.example.net CNAME www.example.com
 *  www.example.net CNAME www2.example.net
 */
BOOST_AUTO_TEST_CASE(test_processCNAME_outoforder) {
  DNSName qname("www.example.com");
  DNSName qname2("www2.example.com");
  DNSName qname3("www.example.net");
  DNSName auth("example.com");
  DNSName newtarget;
  QType qtype = QType(1);
  vector<DNSRecord> ret;

  LWResult lwr;
  lwr.d_rcode = RCode::NoError;
  lwr.d_aabit = true;

  DNSRecord record;
  record.d_name = qname;
  record.d_type = qtype.getCode();
  record.d_place = DNSResourceRecord::QUESTION;
  lwr.d_records.push_back(record);

  DNSRecord record2;
  record2.d_name = qname2;
  record2.d_type = QType::CNAME;
  CNAMERecordContent content2 = CNAMERecordContent(qname3);
  record2.d_content = std::make_shared<CNAMERecordContent>(content2);
  lwr.d_records.push_back(record2);

  DNSRecord record3;
  record3.d_name = qname;
  record3.d_type = QType::CNAME;
  CNAMERecordContent content(qname2);
  record3.d_content = std::make_shared<CNAMERecordContent>(content);
  lwr.d_records.push_back(record3);

  int res = processCNAMEs(lwr, qname, qtype, auth, ret, newtarget);

  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(newtarget, qname3);
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
  lwr.d_rcode = RCode::NoError;
  lwr.d_aabit = true;

  DNSRecord record;
  record.d_name = qname;
  record.d_type = qtype.getCode();
  record.d_place = DNSResourceRecord::QUESTION;
  lwr.d_records.push_back(record);

  DNSRecord record2;
  record2.d_name = qname;
  record2.d_type = QType::A;
  ARecordContent content2 = ARecordContent("192.0.2.1");
  record2.d_content = std::make_shared<ARecordContent>(content2);
  lwr.d_records.push_back(record2);

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
  lwr.d_rcode = RCode::NoError;
  lwr.d_aabit = false;

  DNSRecord record;
  record.d_name = qname;
  record.d_type = QType::A;
  record.d_place = DNSResourceRecord::QUESTION;
  lwr.d_records.push_back(record);

  record.d_name = nsname;
  record.d_type = QType::NS;
  record.d_place = DNSResourceRecord::AUTHORITY;
  NSRecordContent ns("ns1.example.com");
  record.d_content = std::make_shared<NSRecordContent>(ns);
  lwr.d_records.push_back(record);

  NSRecordContent ns2("ns2.example.com");
  record.d_content = std::make_shared<NSRecordContent>(ns2);
  lwr.d_records.push_back(record);

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
  lwr.d_rcode = RCode::NoError;
  lwr.d_aabit = false;

  DNSRecord record;
  record.d_name = qname;
  record.d_type = QType::A;
  record.d_place = DNSResourceRecord::QUESTION;
  lwr.d_records.push_back(record);

  record.d_name = nsname;
  record.d_type = QType::NS;
  record.d_place = DNSResourceRecord::AUTHORITY;
  NSRecordContent ns("ns1.example.com");
  record.d_content = std::make_shared<NSRecordContent>(ns);
  lwr.d_records.push_back(record);

  NSRecordContent ns2("ns2.example.com");
  record.d_content = std::make_shared<NSRecordContent>(ns2);
  lwr.d_records.push_back(record);

  int res = processReferral(lwr, qname, auth, newauth, nsset);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(nsset.size(), 2);
  BOOST_CHECK_EQUAL(newauth, nsname);
}

BOOST_AUTO_TEST_CASE(test_referral_upward) {
  DNSName qname("www.example.com");
  DNSName nsname(".");
  DNSName auth("com");
  DNSName newauth;
  set<DNSName> nsset;

  LWResult lwr;
  lwr.d_rcode = RCode::NoError;
  lwr.d_aabit = false;

  DNSRecord record;
  record.d_name = qname;
  record.d_type = QType::A;
  record.d_place = DNSResourceRecord::QUESTION;
  lwr.d_records.push_back(record);

  record.d_name = nsname;
  record.d_type = QType::NS;
  record.d_place = DNSResourceRecord::AUTHORITY;
  NSRecordContent ns("ns1.example.com");
  record.d_content = std::make_shared<NSRecordContent>(ns);
  lwr.d_records.push_back(record);

  NSRecordContent ns2("ns2.example.com");
  record.d_content = std::make_shared<NSRecordContent>(ns2);
  lwr.d_records.push_back(record);

  int res = processReferral(lwr, qname, auth, newauth, nsset);
  BOOST_CHECK_EQUAL(res, -1);
  BOOST_CHECK_EQUAL(nsset.size(), 0);
  BOOST_CHECK_EQUAL(newauth, DNSName());
}

BOOST_AUTO_TEST_SUITE_END()
