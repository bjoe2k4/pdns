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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "ws-auth.hh"
#include "json.hh"
#include "dnsname.hh"

struct keyStatus {
  dnsName zone;
  bool ksk;
  struct timeval lastChange;
  uint8_t state;
};

int main(int argc, const char* argv[])
{
  struct sigaction sa;
  sa.sa_handler = &signal_handler;

  for(;;){

    sleep(5);
  }
}



void cleanUp()
{

}

void signal_handler(int signal)
{
  switch(signal) {
    case SIGHUP:
      //reload
      break;
    case SIGINT:
      // save and exit
      exit(0);
    default:
      return;
  }
}
