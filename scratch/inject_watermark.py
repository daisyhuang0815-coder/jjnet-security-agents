import zipfile
import io
import os

tmpl_path = r'C:\Users\Elodie\jjnet-security-agents\templates\JJNET_Incident_Report_Template.docx'
img_path = r'C:\Users\Elodie\jjnet-security-agents\templates\jjnet-watermark.jpg'

with open(img_path, 'rb') as f:
    img_bytes = f.read()

with zipfile.ZipFile(tmpl_path, 'r') as zin:
    files = {item.filename: zin.read(item.filename) for item in zin.infolist()}

# 1. Update [Content_Types].xml to include jpg
ct_xml = files['[Content_Types].xml'].decode('utf-8')
if 'Extension="jpg"' not in ct_xml:
    ct_xml = ct_xml.replace('</Types>', '<Default Extension="jpg" ContentType="image/jpeg"/></Types>')
files['[Content_Types].xml'] = ct_xml.encode('utf-8')

# 2. Add word/media/image_watermark.jpg
files['word/media/image_watermark.jpg'] = img_bytes

# 3. Add word/_rels/header1.xml.rels
header_rels = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rIdWatermark" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/image_watermark.jpg"/>'
    '</Relationships>'
)
files['word/_rels/header1.xml.rels'] = header_rels.encode('utf-8')

# 4. Inject watermark drawing paragraph into word/header1.xml before <w:tbl>
watermark_p = (
    '<w:p><w:pPr><w:pStyle w:val="Header"/><w:spacing w:before="0" w:after="0" w:line="2" w:lineRule="exact"/><w:jc w:val="center"/></w:pPr>'
    '<w:r><w:drawing xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">'
    '<wp:anchor distT="0" distB="0" distL="0" distR="0" simplePos="0" relativeHeight="251658240" behindDoc="1" locked="0" layoutInCell="1" allowOverlap="1">'
    '<wp:simplePos x="0" y="0"/>'
    '<wp:positionH relativeFrom="page"><wp:align>center</wp:align></wp:positionH>'
    '<wp:positionV relativeFrom="page"><wp:align>center</wp:align></wp:positionV>'
    '<wp:extent cx="5040000" cy="4477846"/><wp:effectExtent l="0" t="0" r="0" b="0"/><wp:wrapNone/><wp:docPr id="3" name="JJNET Watermark"/>'
    '<wp:cNvGraphicFramePr><a:graphicFrameLocks noChangeAspect="1"/></wp:cNvGraphicFramePr>'
    '<a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
    '<pic:pic><pic:nvPicPr><pic:cNvPr id="0" name="JJNET"/><pic:cNvPicPr/></pic:nvPicPr>'
    '<pic:blipFill><a:blip r:embed="rIdWatermark"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
    '<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="5040000" cy="4477846"/></a:xfrm>'
    '<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic>'
    '</wp:anchor></w:drawing></w:r></w:p>'
)

hdr_xml = files['word/header1.xml'].decode('utf-8')
# Avoid duplicate injection
if 'rIdWatermark' not in hdr_xml:
    hdr_open_idx = hdr_xml.find('>') + 1
    hdr_xml = hdr_xml[:hdr_open_idx] + watermark_p + hdr_xml[hdr_open_idx:]
    files['word/header1.xml'] = hdr_xml.encode('utf-8')

with zipfile.ZipFile(tmpl_path, 'w', zipfile.ZIP_DEFLATED) as zout:
    for fname, data in files.items():
        zout.writestr(fname, data)

print('Updated template successfully! File size:', os.path.getsize(tmpl_path))
