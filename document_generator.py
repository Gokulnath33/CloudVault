"""
CloudVault Native Office Document & File Generator
Generates valid Microsoft Word (.docx), PowerPoint (.pptx), Excel (.xlsx),
and Text/Code documents directly in memory for MongoDB GridFS storage.
"""

from io import BytesIO
from datetime import datetime
import docx
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

import pptx
from pptx.util import Inches as PptInches, Pt as PptPt
from pptx.dml.color import RGBColor as PptRGBColor

def generate_word_document(title, description, content_body, author="CloudVault User"):
    """
    Generate an authentic Microsoft Word document (.docx).
    Returns binary bytes.
    """
    doc = docx.Document()

    # Document Header Title
    title_p = doc.add_paragraph()
    title_run = title_p.add_run(title.strip() or "Untitled Document")
    title_run.font.name = "Calibri"
    title_run.font.size = Pt(26)
    title_run.font.bold = True
    title_run.font.color.rgb = RGBColor(30, 41, 59)
    title_p.alignment = WD_ALIGN_PARAGRAPH.LEFT

    # Metadata subtitle
    meta_p = doc.add_paragraph()
    meta_run = meta_p.add_run(f"Author: {author}  |  Created: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}")
    meta_run.font.size = Pt(10)
    meta_run.font.italic = True
    meta_run.font.color.rgb = RGBColor(100, 116, 139)

    doc.add_paragraph()  # Blank spacing line

    # Optional Summary/Description section
    if description and description.strip():
        h2 = doc.add_heading("Overview", level=1)
        h2_run = h2.runs[0]
        h2_run.font.color.rgb = RGBColor(79, 70, 229)
        desc_p = doc.add_paragraph(description.strip())
        desc_p.runs[0].font.size = Pt(11)

    # Document Content Body
    h_content = doc.add_heading("Document Content", level=1)
    if h_content.runs:
        h_content.runs[0].font.color.rgb = RGBColor(79, 70, 229)

    lines = content_body.strip().split("\n") if content_body else ["This document was created directly inside CloudVault."]
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("- ") or stripped.startswith("* "):
            p = doc.add_paragraph(stripped[2:], style='List Bullet')
        elif stripped.startswith("# "):
            doc.add_heading(stripped[2:], level=2)
        elif stripped:
            p = doc.add_paragraph(stripped)
            p.runs[0].font.size = Pt(11)
            p.paragraph_format.line_spacing = 1.2
        else:
            doc.add_paragraph()

    # Footer note
    doc.add_paragraph()
    footer_p = doc.add_paragraph("— Generated securely in CloudVault File Storage Portal")
    footer_p.runs[0].font.size = Pt(9)
    footer_p.runs[0].font.italic = True
    footer_p.runs[0].font.color.rgb = RGBColor(148, 163, 184)

    buf = BytesIO()
    doc.save(buf)
    return buf.getvalue()

def generate_excel_spreadsheet(sheet_name, title, headers, rows=None):
    """
    Generate an authentic Microsoft Excel Spreadsheet (.xlsx).
    Returns binary bytes.
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = (sheet_name.strip() or "Sheet1")[:30]

    # Theme colors
    header_fill = PatternFill(start_color="312E81", end_color="312E81", fill_type="solid")  # Indigo-900
    header_font = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    title_font = Font(name="Calibri", size=16, bold=True, color="1E1B4B")
    border_side = Side(border_style="thin", color="CBD5E1")
    cell_border = Border(left=border_side, right=border_side, top=border_side, bottom=border_side)
    alt_fill = PatternFill(start_color="F8FAFC", end_color="F8FAFC", fill_type="solid")

    # Row 1: Title Banner
    ws.merge_cells("A1:E1")
    ws["A1"] = title.strip() or "CloudVault Spreadsheet"
    ws["A1"].font = title_font
    ws["A1"].alignment = Alignment(vertical="center")
    ws.row_dimensions[1].height = 32

    # Row 2: Subtitle timestamp
    ws.merge_cells("A2:E2")
    ws["A2"] = f"Created on {datetime.now().strftime('%Y-%m-%d %H:%M')} via CloudVault"
    ws["A2"].font = Font(name="Calibri", size=9, italic=True, color="64748B")
    ws.row_dimensions[2].height = 18

    # Row 4: Column Headers
    header_row_idx = 4
    if not headers:
        headers = ["ID", "Item Name", "Category", "Quantity", "Amount (INR)", "Status"]

    for col_idx, header_text in enumerate(headers, start=1):
        cell = ws.cell(row=header_row_idx, column=col_idx, value=header_text)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = cell_border
    ws.row_dimensions[header_row_idx].height = 24

    # Data Rows
    if not rows:
        rows = [
            [1, "Product Design Specs", "Engineering", 1, 45000, "Completed"],
            [2, "Cloud Hosting Server", "Infrastructure", 12, 12000, "Active"],
            [3, "Database Storage Cluster", "Storage", 1, 8500, "Active"],
            [4, "Office Document Tools", "Software", 5, 15000, "Pending Review"],
            [5, "Security Audit Certification", "Compliance", 1, 30000, "Scheduled"]
        ]

    for row_idx, row_data in enumerate(rows, start=header_row_idx + 1):
        ws.row_dimensions[row_idx].height = 20
        is_even = (row_idx % 2 == 0)
        for col_idx, val in enumerate(row_data, start=1):
            cell = ws.cell(row=row_idx, column=col_idx, value=val)
            cell.font = Font(name="Calibri", size=10)
            cell.border = cell_border
            if is_even:
                cell.fill = alt_fill
            # Align numbers right, text left
            if isinstance(val, (int, float)):
                cell.alignment = Alignment(horizontal="right", vertical="center")
            else:
                cell.alignment = Alignment(horizontal="left", vertical="center")

    # Auto-fit column widths
    for col in ws.columns:
        max_len = max(len(str(cell.value or '')) for cell in col)
        col_letter = get_column_letter(col[0].column)
        ws.column_dimensions[col_letter].width = max(max_len + 4, 14)

    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()

def generate_powerpoint_presentation(title, subtitle, slides_content=None, presenter="CloudVault"):
    """
    Generate an authentic Microsoft PowerPoint Presentation (.pptx).
    Returns binary bytes.
    """
    prs = pptx.Presentation()
    prs.slide_width = PptInches(13.333)  # Modern 16:9 widescreen
    prs.slide_height = PptInches(7.5)

    # Slide 1: Title Slide
    title_slide_layout = prs.slide_layouts[0]
    slide1 = prs.slides.add_slide(title_slide_layout)
    
    title_shape = slide1.shapes.title
    title_shape.text = title.strip() or "CloudVault Presentation"
    if title_shape.text_frame.paragraphs:
        p = title_shape.text_frame.paragraphs[0]
        p.font.size = PptPt(44)
        p.font.bold = True
        p.font.color.rgb = PptRGBColor(49, 46, 129)  # Indigo-900

    subtitle_shape = slide1.placeholders[1]
    sub_text = subtitle.strip() or "Modern File Storage & Collaboration Portal"
    subtitle_shape.text = f"{sub_text}\nPresented by: {presenter}  |  {datetime.now().strftime('%B %Y')}"
    if subtitle_shape.text_frame.paragraphs:
        for p in subtitle_shape.text_frame.paragraphs:
            p.font.size = PptPt(18)
            p.font.color.rgb = PptRGBColor(100, 116, 139)

    # Content Slides
    if not slides_content:
        slides_content = [
            {
                "title": "Project Overview & Capabilities",
                "bullets": [
                    "Isolated, multi-user encrypted private storage vaults",
                    "Native support for Word, PowerPoint, Excel, and Images",
                    "Real-time OTP verification & Administrator approval gate",
                    "Direct streaming and previews from MongoDB GridFS Cloud cluster"
                ]
            },
            {
                "title": "Storage Architecture & Security",
                "bullets": [
                    "High-availability MongoDB Atlas replica set storage",
                    "Role-based access control protecting user privacy",
                    "Granular audit trails tracking file uploads and downloads",
                    "Zero local disk dependency during cloud deployments"
                ]
            },
            {
                "title": "Next Steps & Roadmap",
                "bullets": [
                    "In-browser document editing and folder tagging",
                    "Automated virus scanning and integrity checksums",
                    "Team workspace collaboration and shared vaults"
                ]
            }
        ]

    bullet_slide_layout = prs.slide_layouts[1]
    for slide_data in slides_content:
        slide = prs.slides.add_slide(bullet_slide_layout)
        
        # Slide Title
        stitle = slide.shapes.title
        stitle.text = slide_data.get("title", "Slide Title")
        if stitle.text_frame.paragraphs:
            sp = stitle.text_frame.paragraphs[0]
            sp.font.size = PptPt(32)
            sp.font.bold = True
            sp.font.color.rgb = PptRGBColor(30, 41, 59)

        # Slide Body Bullets
        body_shape = slide.shapes.placeholders[1]
        tf = body_shape.text_frame
        tf.clear()

        bullets = slide_data.get("bullets", [])
        for idx, bullet_text in enumerate(bullets):
            p = tf.add_paragraph() if idx > 0 else tf.paragraphs[0]
            p.text = bullet_text
            p.font.size = PptPt(20)
            p.font.color.rgb = PptRGBColor(71, 85, 105)
            p.level = 0
            p.space_after = PptPt(14)

    buf = BytesIO()
    prs.save(buf)
    return buf.getvalue()

def generate_text_document(title, content):
    """Generate a clean text / markdown document bytes."""
    header = f"# {title}\nCreated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} via CloudVault\n\n"
    full_text = header + (content or "")
    return full_text.encode("utf-8")

