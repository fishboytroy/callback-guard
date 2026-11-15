# Detection fixture (inert): shows import-indirection + split-string evasion
# that keyword scanners miss. Not a working attack and never executed by the
# scanner, which only reads the bytes. Phase 3's AST analyzer resolves the
# assembled name and the alias, so this is held as process-execution.
import importlib

mod = importlib.import_module('sub' + 'process')
runner = getattr(mod, 'Po' + 'pen')
runner(['cmd', '/c', 'whoami'])
