"""PDF incident report generation. Evidence hashes are integrity aids, not legal chain-of-custody guarantees."""
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from xml.sax.saxutils import escape

def make_pdf(a):
    buf=BytesIO(); doc=SimpleDocTemplate(buf,pagesize=A4,rightMargin=16*mm,leftMargin=16*mm,topMargin=15*mm,bottomMargin=15*mm)
    styles=getSampleStyleSheet(); styles.add(ParagraphStyle(name='SmallMono',parent=styles['BodyText'],fontName='Courier',fontSize=7,leading=9,wordWrap='CJK'))
    story=[Paragraph('PHISHGUARD 2.0 — EMAIL FORENSICS REPORT',styles['Title']),Paragraph('Defensive triage report · Local-first analysis',styles['Normal']),Spacer(1,8*mm)]
    rows=[['Analysis ID',str(a.get('id','N/A'))],['Subject',escape(a.get('subject',''))],['Sender',escape(a.get('sender',''))],['Verdict / severity',f"{escape(a.get('verdict',''))} / {escape(a.get('severity',''))}"],['Risk index',f"{a.get('risk_score',0)}/100 (not a probability)"],['Technique',escape(a.get('technique',''))],['Analyzed at',escape(a.get('analyzed_at',''))],['Message SHA-256',escape(a.get('raw_sha256',''))]]
    t=Table(rows,colWidths=[42*mm,135*mm]); t.setStyle(TableStyle([('BACKGROUND',(0,0),(0,-1),colors.HexColor('#eef2f7')),('GRID',(0,0),(-1,-1),.3,colors.HexColor('#d6dde6')),('VALIGN',(0,0),(-1,-1),'TOP'),('PADDING',(0,0),(-1,-1),6)])); story += [t,Spacer(1,6*mm),Paragraph('Executive assessment',styles['Heading2']),Paragraph(escape(a.get('reasoning','')),styles['BodyText']),Spacer(1,4*mm),Paragraph('Evidence findings',styles['Heading2'])]
    sig=a.get('signals',[])
    if sig:
        for s in sig: story.append(Paragraph(f"• <b>{escape(s.get('title',''))}</b> (+{s.get('points',0)}): {escape(s.get('detail',''))}",styles['BodyText']))
    else: story.append(Paragraph('No high-risk heuristic indicators were found. This does not prove the message is safe.',styles['BodyText']))
    story += [Spacer(1,4*mm),Paragraph('Authentication observations',styles['Heading2'])]
    auth=a.get('authentication',{}); story.append(Paragraph(' · '.join(f'{k.upper()}: {v}' for k,v in auth.items()),styles['BodyText']))
    story += [Spacer(1,4*mm),Paragraph('URLs and domains',styles['Heading2'])]
    for u in a.get('urls',[]): story.append(Paragraph(escape(u.get('url',''))+' — '+escape(', '.join(u.get('flags',[])) or 'No lexical flags'),styles['SmallMono']))
    story += [Spacer(1,4*mm),Paragraph('Attachments',styles['Heading2'])]
    for f in a.get('attachments',[]): story.append(Paragraph(f"{escape(f.get('filename',''))} · {f.get('size',0)} bytes · SHA-256 {escape(f.get('sha256',''))} · {escape(f.get('magic_type','unknown'))}",styles['SmallMono']))
    story += [Spacer(1,6*mm),Paragraph('Analyst note',styles['Heading2']),Paragraph('This report is an automated aid. Receiver-stamped SPF/DKIM/DMARC results are observations, not fresh cryptographic verification. URLs are not fetched and attachments are not executed. Validate findings in context before response actions. A SHA-256 hash supports integrity checking but does not alone establish legal chain of custody.',styles['BodyText']),Spacer(1,3*mm),Paragraph('Employee coaching: '+escape(a.get('coaching_message','')),styles['BodyText'])]
    doc.build(story); buf.seek(0); return buf
