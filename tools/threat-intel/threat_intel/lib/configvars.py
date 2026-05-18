"""Process-wide mutable state shared across modules.

Set by intel-cli.py based on command-line flags; read by lib/ and modules/.
"""

bkg = 1
output_dir = '.'
proxy = ''
output_format = 'text'
verbosity = 0
cache_enabled = True
cache_ttl = 3600
