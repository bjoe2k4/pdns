/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2001 - 2016  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnsseckeeper.hh"

/**
 * Goes through the records in records and fills semantics based on the information
 * found
 *
 * @param zname     The name of the zone so out-of-zone data is ignored
 * @param records   A vector of DNSResourceRecords to go through
 * @param semantics A struct guessedZoneSemantics that is edited based on
 *                  the records found in records
 */
void DNSSECKeeper::guessZoneSemantics(const DNSName& zname, const vector<DNSResourceRecord>& records, DNSSECKeeper::guessedZoneSemantics& semantics)
{
  bool firstNSEC3 = true;
  for(const auto rr :  records) {
    if(! rr.qname.isPartOf(zname))
        continue;

    switch(rr.qtype.getCode()) {
      case QType::NSEC3PARAM: {
        semantics.ns3pr = NSEC3PARAMRecordContent(rr.content);
        semantics.isDnssecZone = semantics.isNSEC3 = true;
        semantics.isNarrow = false;
        continue;
      }
      case QType::NSEC3: {
        NSEC3RecordContent ns3rc(rr.content);
        if (firstNSEC3) {
          semantics.isDnssecZone = semantics.isPresigned = true;
          firstNSEC3 = false;
        } else if (semantics.optOutFlag != (ns3rc.d_flags & 1))
          throw PDNSException("Zones with a mixture of Opt-Out NSEC3 RRs and non-Opt-Out NSEC3 RRs are not supported.");
        semantics.optOutFlag = ns3rc.d_flags & 1;
        continue;
      }
      case QType::NSEC: {
        semantics.isDnssecZone = semantics.isPresigned = true;
        continue;
      }
    }
  }
  if(semantics.isNSEC3) {
    semantics.ns3pr.d_flags = semantics.optOutFlag ? 1 : 0;
  }
}
