import importlib.machinery
import importlib.util
import os
import shutil
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Not under /tmp: the launcher refuses projects there.
TMP_BASE = os.path.join(ROOT, "tests", ".tmp")


def scratch_dir(test):
    os.makedirs(TMP_BASE, exist_ok=True)
    path = os.path.realpath(tempfile.mkdtemp(dir=TMP_BASE))
    test.addCleanup(shutil.rmtree, path, True)
    return path


def load_launcher():
    loader = importlib.machinery.SourceFileLoader("pithos", os.path.join(ROOT, "pithos"))
    spec = importlib.util.spec_from_loader("pithos", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module
