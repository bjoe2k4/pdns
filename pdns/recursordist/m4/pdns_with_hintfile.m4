AC_DEFUN([PDNS_WITH_HINTFILE],[
  AC_ARG_WITH([hint-file],
    [AS_HELP_STRING([--with-hint-file=PATH], [path to default root-hints file used @<:@default=empty@:>@])],
    [with_hintfile=$withval],
    [with_hintfile=])
  AC_DEFINE_UNQUOTED([HINTFILE],
    ["$with_hintfile"],
    [Path to the default root-hints file])
])
