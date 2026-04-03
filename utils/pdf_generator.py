from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

def generate_pdf(email, data):
    file_path = f"reports/{email}.pdf"
    doc = SimpleDocTemplate(file_path)
    styles = getSampleStyleSheet()

    content = []
    content.append(Paragraph(f"Report for {email}", styles["Title"]))

    for item in data:
        text = f"{item['name']} - {item['date']} - Severity {item['severity']}"
        content.append(Paragraph(text, styles["Normal"]))

    doc.build(content)
    return file_path