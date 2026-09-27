"""
sotrace-lldb.py — LLDB command script entry point.

Load in LLDB:
    (lldb) command script import /path/to/plugins/sotrace-lldb/sotrace-lldb.py

This registers the 'sotrace-trace' command.

Usage:
    (lldb) sotrace-trace --server http://192.168.1.83:3000 --so libfoo.so --steps 5000
    (lldb) sotrace-trace --output /tmp/trace.jsonl --so libfoo.so --steps 2000
    (lldb) sotrace-trace --server http://192.168.1.83:3000 --so-base 0x71000000 --so-size 0x100000 --steps 3000
"""

import sys
import os

# Make sotrace_lldb importable relative to this file's directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        'command script add -f sotrace_lldb_entry.invoke sotrace-trace'
    )
    print('[sotrace] Plugin loaded. Run: sotrace-trace --help')


def invoke(debugger, command, exe_ctx, result, internal_dict):
    """Dispatched by LLDB for the 'sotrace-trace' command."""
    import shlex
    import argparse

    parser = argparse.ArgumentParser(prog='sotrace-trace', add_help=True)
    parser.add_argument('--server',   default='',  help='sotrace-server URL')
    parser.add_argument('--output',   default='',  help='JSONL output file path')
    parser.add_argument('--so',       default='',  help='SO filename to filter (e.g. libfoo.so)')
    parser.add_argument('--so-base',  default='0', help='SO load address (hex, e.g. 0x71000000)')
    parser.add_argument('--so-size',  default='0', help='SO size in bytes (hex or dec)')
    parser.add_argument('--steps',    type=int, default=10000, help='Max stepi count')
    parser.add_argument('--thread',   type=int, default=None, help='Thread ID to trace (default: selected)')

    try:
        args = parser.parse_args(shlex.split(command))
    except SystemExit:
        return  # --help printed by argparse

    if not args.server and not args.output:
        result.SetError('[sotrace] Specify --server or --output (or both)')
        return

    so_base = int(args.so_base, 16) if args.so_base.startswith('0x') else int(args.so_base, 0)
    so_size = int(args.so_size, 16) if args.so_size.startswith('0x') else int(args.so_size, 0)

    from sotrace_lldb.plugin import SoTracePlugin

    plugin = SoTracePlugin(
        debugger,
        server_url  = args.server or None,
        so_name     = args.so,
        so_base     = so_base,
        so_size     = so_size,
        max_steps   = args.steps,
        target_tid  = args.thread,
        output_file = args.output,
    )

    try:
        plugin.attach()
        result.AppendMessage(
            f'[sotrace] Tracing {args.steps} steps'
            + (f' in {args.so}' if args.so else '')
            + (f'  server={args.server}' if args.server else '')
        )
        plugin.run()
        trace_id = plugin.flush()

        msg = f'[sotrace] Done  instructions={plugin.batcher.size()}  trace_id={trace_id}'
        if args.server and trace_id:
            msg += f'\n         Analyze: {args.server}/api/v1/traces/{trace_id}/analyze/threads/races'
        result.AppendMessage(msg)
    except Exception as e:
        result.SetError(f'[sotrace] Error: {e}')


# Module-level alias so LLDB can locate the function via dotted path
import sys as _sys
_mod = _sys.modules[__name__]
setattr(_mod, 'sotrace_lldb_entry', type(_sys)('sotrace_lldb_entry'))
_sys.modules['sotrace_lldb_entry'] = _mod  # self-alias for HandleCommand lookup
