"""PATH-002: Safe - Static path, no user input used in open()."""
def read_config():
    with open('/app/config.json') as fh:
        return fh.read()

