Running and Operating PowerDNS
==============================

PowerDNS is normally controlled via a SysV-style init.d script, often
located in ``/etc/init.d`` or ``/etc/rc.d/init.d``. For Linux
distributions with systemd, a service file is provided (either in the
package or in the contrib directory of the tarball).

Furthermore, PowerDNS can be run on the foreground for testing or in
other init- systems that supervise processes.

Guardian
--------

When the init-system of the Operating System does not properly
supervises processes, like SysV init, it is recommended to run PowerDNS
with the ```guardian`` <settings.md#guardian>`__ option set to 'yes'.

When launched with ``guardian=yes``, ``pdns_server`` wraps itself inside
a 'guardian'. This guardian monitors the performance of the inner
``pdns_server`` instance which shows up in the process list of your OS
as ``pdns_server-instance``. It is also this guardian that
:ref:`running-pdnscontrol` talks to. A **STOP** is interpreted
by the guardian, which causes the guardian to sever the connection to
the inner process and terminate it, after which it terminates itself.
Requests that require data from the actual nameserver are passed to the
inner process as well.

Logging to syslog on systemd-based operating systems
----------------------------------------------------

By default, logging to syslog is disabled in the the systemd unit file
to prevent the service logging twice, as the systemd journal picks up
the output from the process itself.

Removing the ``--disable-syslog`` option from the ``ExecStart`` line
using ``systemctl edit --full pdns`` enables logging to syslog.

Controlling A Running PowerDNS Server
-------------------------------------

As a DNS server is critical infrastructure, downtimes should be avoided
as much as possible. Even though PowerDNS (re)starts very fast, it
offers a way to control it while running.

Control Socket
~~~~~~~~~~~~~~

The controlsocket is the means to contact a running PowerDNS process.
Over this socket, instructions can be sent using the ``pdns_control``
program. The control socket is called ``pdns.controlsocket`` and is
created inside the ```socket-dir`` <settings.md#socket-dir>`__.

.. _running-pdnscontrol:

``pdns_control``
~~~~~~~~~~~~~~~~

To communicate with PowerDNS Authoritative Server over the
controlsocket, the ``pdns_control`` command is used. The syntax is
simple: ``pdns_control command arguments``. Currently this is most
useful for telling backends to rediscover domains or to force the
transmission of notifications. See `Master
Operation <../authoritative/modes-of-operation.md#master-operation>`__.

For all supported ``pdns_control`` commands and options, see `the
manpage <../manpages/pdns_control.1>`__ and the output of
``pdns_control --help`` on your system.

The SysV init script
--------------------

This script supplied with the PowerDNS source accepts the following
commands:

-  ``monitor``: Monitor is a special way to view the daemon. It executes
   PowerDNS in the foreground with a lot of logging turned on, which
   helps in determining startup problems. Besides running in the
   foreground, the raw PowerDNS control socket is made available. All
   external communication with the daemon is normally sent over this
   socket. While useful, the control console is not an officially
   supported feature. Commands which work are: ``QUIT``, ``SHOW *``,
   ``SHOW varname``, ``RPING``.
-  ``start``: Start PowerDNS in the background. Launches the daemon but
   makes no special effort to determine success, as making database
   connections may take a while. Use ``status`` to query success. You
   can safely run ``start`` many times, it will not start additional
   PowerDNS instances.
-  ``restart``: Restarts PowerDNS if it was running, starts it
   otherwise.
-  ``status``: Query PowerDNS for status. This can be used to figure out
   if a launch was successful. The status found is prefixed by the PID
   of the main PowerDNS process.
-  ``stop``: Requests that PowerDNS stop. Again, does not confirm
   success. Success can be ascertained with the ``status`` command.
-  ``dump``: Dumps a lot of statistics of a running PowerDNS daemon. It
   is also possible to single out specific variable by using the
   ``show`` command.
-  ``show variable``: Show a single statistic, as present in the output
   of the ``dump``.
-  ``mrtg``: Dump statistics in mrtg format. See the performance
   `monitoring <../common/logging.md#performance-monitoring>`__
   documentation.

**Note**: Packages provided by Operating System vendors might support
different or less commands.

Running in the foreground
-------------------------

One can run PowerDNS in the foreground by invoking the ``pdns_server``
executable. Without any options, it will load the ``pdns.conf`` and run.
To make sure PowerDNS starts in the foreground, add the ``--daemon=no``
option.

All :doc:`settings <settings>` can be added on the commandline. e.g. to
test a new database config, you could start PowerDNS like this:

.. code-block:: shell

    pdns_server --no-config --daemon=no --local-port=5300 --launch=gmysql --gmysql-user=my_user --gmysql-password=mypassword

This starts PowerDNS without loading on-disk config, in the foreground,
on all network interfaces on port 5300 and starting the
:doc:`gmysql <backends/generic-mysql>` backend.
