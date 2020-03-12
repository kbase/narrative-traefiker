import app


def on_starting(server):
    app.setup_app(app.app)
