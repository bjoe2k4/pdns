#include "validate-recursor.hh"
#include "validate.hh"

DNSSECMode g_dnssecvalidation{DNSSECMode::Off};
DNSSECMode g_dnssecservfail{DNSSECMode::On};
DNSSECLog g_dnsseclog{DNSSECLog::Off};

bool checkDNSSECDisabled() {
  return warnIfDNSSECDisabled("");
}

bool warnIfDNSSECDisabled(const string& msg) {
  if(g_dnssecvalidation == DNSSECMode::Off) {
    if (!msg.empty())
      L<<Logger::Warning<<msg<<endl;
    return true;
  }
  return false;
}

vState validateRecords(const vector<DNSRecord>& recs, const bool& tracedQuery)
{
  if(recs.empty())
    return Insecure; // can't secure nothing 

  g_stats.dnssecValidations++;
  DNSSECValidator validator(tracedQuery);
  auto state = validator.validateRecords(recs);
  g_stats.dnssecResults[state]++;
  if (state == NTA)
    state = Insecure;
  return state;
}
