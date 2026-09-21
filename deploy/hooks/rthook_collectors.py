import sys
import os

if hasattr(sys, '_MEIPASS'):
    os.environ.setdefault('INSIEDR_COLLECTORS_DIR', os.path.join(sys._MEIPASS, 'agent', 'collectors'))
