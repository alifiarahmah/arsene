from markdown_pdf import MarkdownPdf

md = """
# Test

## Subheading
April showed moderate sales growth...

| Category | Revenue | Units Sold |
|---------------|----------|-------------|
| Electronics | $32,500 | 850 |
| Home Goods | $21,300 | 1,120 |
| Personal Care | $14,200 | 980 |
| **Total** | $68,000 | 2,950 |
"""

pdf = MarkdownPdf()
pdf.add_section(md)
pdf.save("report.pdf")