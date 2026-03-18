# pdf_generator.py — Renders report data into a styled PDF using WeasyPrint

import os
from weasyprint import HTML, CSS
from jinja2 import Environment, FileSystemLoader

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), '..', 'templates')


def generate_pdf(report_data, output_path):
    """
    Renders the report HTML template with report_data,
    then converts it to a PDF file at output_path.
    """
    # Load Jinja2 template
    env      = Environment(loader=FileSystemLoader(TEMPLATES_DIR))
    template = env.get_template('report_template.html')

    # Render HTML string
    html_content = template.render(**report_data)

    # Convert HTML → PDF
    HTML(string=html_content, base_url=TEMPLATES_DIR).write_pdf(output_path)

    return output_path