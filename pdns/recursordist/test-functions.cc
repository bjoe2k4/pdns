#include "test-functions.hh"
#include "dnsrecords.hh"

void setLWResult(LWResult* res, int rcode, bool aa, bool tc, bool edns)
{
  res->d_rcode = rcode;
  res->d_aabit = aa;
  res->d_tcbit = tc;
  res->d_haveEDNS = edns;
}

void addRecordToLW(LWResult* res, const DNSName& name, uint16_t type, const std::string& content, DNSResourceRecord::Place place, uint32_t ttl)
{
  DNSRecord rec;
  rec.d_place = place;
  rec.d_name = name;
  rec.d_type = type;
  rec.d_ttl = ttl;

  if (type == QType::NS) {
    rec.d_content = std::make_shared<NSRecordContent>(DNSName(content));
  }
  else if (type == QType::A) {
    rec.d_content = std::make_shared<ARecordContent>(ComboAddress(content));
  }
  else if (type == QType::AAAA) {
    rec.d_content = std::make_shared<AAAARecordContent>(ComboAddress(content));
  }
  else if (type == QType::CNAME) {
    rec.d_content = std::make_shared<CNAMERecordContent>(DNSName(content));
  }
  else {
    rec.d_content = shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(type, QClass::IN, content));
  }

  res->d_records.push_back(rec);
}

void addRecordToLW(LWResult* res, const std::string& name, uint16_t type, const std::string& content, DNSResourceRecord::Place place, uint32_t ttl)
{
  addRecordToLW(res, DNSName(name), type, content, place, ttl);
}
