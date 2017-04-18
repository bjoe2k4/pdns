#pragma once
#include "dnsrecords.hh"
#include "lwres.hh"

static void setLWResult(LWResult* res, int rcode, bool aa=false, bool tc=false, bool edns=false)
{
  res->d_rcode = rcode;
  res->d_aabit = aa;
  res->d_tcbit = tc;
  res->d_haveEDNS = edns;
}

static void addRecordToList(std::vector<DNSRecord>& records, const DNSName& name, uint16_t type, const std::string& content, DNSResourceRecord::Place place, uint32_t ttl)
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
  else if (type == QType::OPT) {
    rec.d_content = std::make_shared<OPTRecordContent>();
  }
  else {
    rec.d_content = shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(type, QClass::IN, content));
  }

  records.push_back(rec);
}

static void addRecordToList(std::vector<DNSRecord>& records, const std::string& name, uint16_t type, const std::string& content, DNSResourceRecord::Place place, uint32_t ttl)
{
  addRecordToList(records, name, type, content, place, ttl);
}

static void addRecordToLW(LWResult* res, const DNSName& name, uint16_t type, const std::string& content, DNSResourceRecord::Place place=DNSResourceRecord::ANSWER, uint32_t ttl=60)
{
  addRecordToList(res->d_records, name, type, content, place, ttl);
}

static void addRecordToLW(LWResult* res, const std::string& name, uint16_t type, const std::string& content, DNSResourceRecord::Place place=DNSResourceRecord::ANSWER, uint32_t ttl=60)
{
  addRecordToLW(res, DNSName(name), type, content, place, ttl);
}

