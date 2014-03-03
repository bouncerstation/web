from flask import Flask
app = Flask("bsweb")

from modules import core
app.register_blueprint(core.app)
