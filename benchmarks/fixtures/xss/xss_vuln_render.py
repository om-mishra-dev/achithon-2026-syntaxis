"""XSS-001: Vulnerable - render_template_string with request.args user input (Flask XSS)."""
from flask import request, render_template_string


def greet():
    name = request.args.get('name')
    return render_template_string(f'<h1>Hello {name}</h1>')

