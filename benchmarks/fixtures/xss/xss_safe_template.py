"""XSS-002: Safe - render_template uses autoescaping; user input not directly inserted."""
from flask import request, render_template


def greet():
    name = request.args.get('name')
    return render_template('index.html', name=name)

