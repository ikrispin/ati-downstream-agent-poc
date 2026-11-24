"""Build the LSCore visual guide using the configured bundled artifact runtime.

Run with that runtime's Python and pass its dependency directory as --runtime-root.
Diagram SVGs and PNGs are kept beside this source; rendered document QA is separate.
"""

import argparse
import html
import json
import subprocess
from pathlib import Path

from docx import Document
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
OUT = BASE / "LSCore-integration-visual-guide.docx"
ASSETS = HERE / "diagrams"

INK = "#17212B"
MUTED = "#4D5A68"
GRAY = "#F3F5F7"
BORDER = "#ACB7C3"
BLUE = "#EAF2FC"
BLUE_LINE = "#3E6A9C"
TEAL = "#E8F5F1"
TEAL_LINE = "#247565"
AMBER = "#FFF4DF"
AMBER_LINE = "#9A6A19"


class Diagram:
    def __init__(self, height):
        self.height = height
        self.items = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="1080" height="{height}" '
            f'viewBox="0 0 1080 {height}">',
            '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
            'markerWidth="8" markerHeight="8" orient="auto-start-reverse">'
            f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{MUTED}"/></marker></defs>',
            '<rect width="100%" height="100%" fill="white"/>',
        ]

    def text(self, x, y, lines, size=24, weight=400, color=INK, anchor="middle", gap=None):
        lines = [lines] if isinstance(lines, str) else lines
        gap = gap or size * 1.3
        for i, line in enumerate(lines):
            self.items.append(
                f'<text x="{x}" y="{y + i * gap}" text-anchor="{anchor}" '
                f'font-family="DejaVu Sans, sans-serif" font-size="{size}" '
                f'font-weight="{weight}" fill="{color}">{html.escape(line)}</text>'
            )

    def box(self, x, y, w, h, title, body=None, fill=GRAY, stroke=BORDER, size=25):
        self.items.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="2.5"/>'
        )
        title = [title] if isinstance(title, str) else title
        body = [] if body is None else [body] if isinstance(body, str) else body
        rows = [(s, size, 600, INK) for s in title] + [(s, 21, 400, MUTED) for s in body]
        total = sum(s * 1.35 for _, s, _, _ in rows)
        baseline = y + (h - total) / 2
        for line, fs, weight, color in rows:
            baseline += fs * 1.1
            self.text(x + w / 2, baseline, line, fs, weight, color)
            baseline += fs * 0.25

    def group(self, x, y, w, h, title, fill="white", stroke=BORDER):
        self.items.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="15" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="2" stroke-dasharray="9 7"/>'
        )
        self.text(x + 22, y + 35, title, 25, 600, anchor="start")

    def line(self, points, arrow=True, dashed=False, color=MUTED, width=2.7):
        value = " ".join(f"{x},{y}" for x, y in points)
        self.items.append(
            f'<polyline points="{value}" fill="none" stroke="{color}" '
            f'stroke-width="{width}" stroke-linejoin="round" '
            + ('stroke-dasharray="9 7" ' if dashed else "")
            + ('marker-end="url(#arrow)" ' if arrow else "") + '/>'
        )

    def label(self, x, y, text, size=20, anchor="middle", color=MUTED):
        width = len(text) * size * 0.56 + 18
        x0 = x - width / 2 if anchor == "middle" else x - 6
        self.items.append(
            f'<rect x="{x0}" y="{y - size}" width="{width}" height="{size + 8}" '
            'fill="white"/>'
        )
        self.text(x, y, text, size, color=color, anchor=anchor)

    def save(self, name):
        target = ASSETS / f"{name}.svg"
        target.write_text("\n".join(self.items + ["</svg>"]))
        return target


def architecture():
    d = Diagram(720)
    d.box(30, 15, 300, 80, "Headless CVE client", ["One native query per CVE"])
    d.box(745, 15, 300, 80, "MAS A2A node", ["Native agent delegation"])
    d.group(205, 160, 670, 310, "Pinned unmodified LSCore process", fill="#FCFDFE")
    d.box(285, 220, 510, 80, "Native LSCore agent wrapper", ["Conversations task state and retry policy"], BLUE, BLUE_LINE)
    d.box(285, 355, 510, 80, "Embedded OGX", ["Model and MCP tool execution"], BLUE, BLUE_LINE)
    d.line([(180, 95), (180, 260), (285, 260)])
    d.line([(895, 95), (895, 260), (795, 260)])
    d.line([(540, 300), (540, 355)])
    d.box(30, 540, 310, 85, "Model provider", ["Called by native LSCore"])
    d.box(560, 530, 480, 100, "ATI domain MCP tools", ["Source evidence and priority", "Read-only collection and private records"], TEAL, TEAL_LINE)
    d.line([(285, 395), (185, 395), (185, 540)])
    d.line([(795, 395), (920, 395), (920, 530)])
    d.box(505, 672, 260, 42, "Read only sources", size=22)
    d.box(815, 672, 230, 42, "Private records", fill=TEAL, stroke=TEAL_LINE, size=22)
    d.line([(710, 630), (710, 652), (635, 652), (635, 672)])
    d.line([(920, 630), (920, 672)])
    return d.save("01_native_architecture")



def native_loop():
    d = Diagram(760)
    d.box(320, 12, 440, 78, "Prompts profiles and skills",
          ["Supported instruction extensions"], BLUE, BLUE_LINE)
    d.group(20, 130, 1040, 510, "LSCore native execution")
    d.box(300, 190, 480, 80, "Agent wrapper", ["Pydantic AI outer run / retry"], BLUE, BLUE_LINE)
    d.line([(540, 90), (540, 190)])
    d.group(200, 330, 810, 265, "One OGX response has its own allowances", fill="#FCFDFE")
    d.box(235, 420, 200, 80, "Model")
    d.box(505, 420, 210, 80, "read A", ["0.7 seconds"])
    d.box(785, 420, 190, 80, "read B", ["0.7 seconds"])
    d.line([(540, 270), (540, 330)])
    d.line([(435, 460), (505, 460)])
    d.line([(715, 460), (785, 460)])
    d.label(750, 410, "then", 20)
    d.line([(880, 500), (880, 555), (335, 555), (335, 500)])
    d.label(605, 553, "Tool results return to the model", 20)
    d.line([(200, 455), (80, 455), (80, 230), (300, 230)], color=AMBER_LINE)
    d.text(96, 303, ["Outer retry", "can start", "a fresh", "response"], 21,
           color=AMBER_LINE, anchor="start")
    d.box(350, 682, 380, 68, "Final text or run failure", size=25)
    d.line([(605, 595), (605, 660), (540, 660), (540, 682)])
    return d.save("02_native_loop")


def domain_sequence():
    d = Diagram(800)
    lanes = [(125, "LSCore agent", BLUE), (405, "ATI MCP tools", TEAL),
             (680, "Data sources", GRAY), (955, "Domain records", TEAL)]
    for x, label, fill in lanes:
        d.box(x - 110, 12, 220, 67, label, fill=fill, size=22)
        d.line([(x, 79), (x, 785)], arrow=False, dashed=True, color="#B7C1CA", width=1.8)
    def message(a, b, y, label):
        d.line([(a, y), (b, y)])
        d.label((a+b)/2, y-12, label, 20)
    message(125, 405, 145, "1  Collect one named source")
    message(405, 955, 220, "2  Reserve the registered CVE observation")
    message(405, 680, 295, "3  Read bounded source data")
    message(680, 405, 365, "4  Evidence or source failure")
    message(405, 955, 435, "5  Save observation including safe failure details")
    message(405, 125, 505, "6  Return selected facts")
    message(125, 405, 600, "7  Finalize recorded evidence")
    message(405, 955, 675, "8  Read evidence compute priority and save")
    message(405, 125, 755, "9  Domain outcome and priority")
    return d.save("03_domain_tools_sequence")



def journey():
    d = Diagram(865)
    d.box(215, 12, 650, 78, "Headless CVE list and environment", ["Register scope; default 2 native requests at once"], GRAY)
    d.line([(540, 90), (540, 145)])
    d.group(20, 145, 1040, 355, "Six fetching operations chosen by native LSCore")
    for x,y,title,body in [
        (55,210,"Red Hat security data","Vendor CVE evidence"),
        (575,210,"Public OSIDB","Public flaw and affect evidence"),
        (55,307,"Lightspeed MCP: CVE","CVE details; one MCP connection"),
        (575,307,"Lightspeed MCP: fleet","Affected hosts; same MCP connection"),
        (55,404,"Existing Support MCP","CVE search and relevance checks"),
        (575,404,"Public HTTP threat feeds","FIRST EPSS, CVE.org and CISA KEV"),
    ]:
        d.box(x,y,450,73,title,[body],size=23)
    d.line([(540,500),(540,547)])
    d.box(150,547,780,80,"Native agent calls finalize_cve_assessment", ["ATI computes priority from saved observations"], TEAL, TEAL_LINE,size=24)
    d.line([(540,627),(540,680)])
    d.box(175,680,730,70,"LSCore produces the final answer text", ["Its native A2A task does not carry ATI typed JSON"],BLUE,BLUE_LINE,size=24)
    d.line([(540,750),(540,793)])
    d.box(155,793,770,62,"Headless client exports the domain record separately",fill=TEAL,stroke=TEAL_LINE,size=24)
    return d.save("04_journey_assessment")



def failure_boundaries():
    d = Diagram(720)
    d.box(310,15,460,85,"Native LSCore execution",["Model calls scheduling and retries"],BLUE,BLUE_LINE)
    d.line([(540,100),(540,140),(245,140),(245,190)])
    d.line([(540,140),(835,140),(835,190)])
    d.box(30,190,430,90,"ATI domain MCP call",["One source read or finalization"],TEAL,TEAL_LINE)
    d.box(620,190,430,90,"OGX model inference",["Provider SDK may retry"],BLUE,BLUE_LINE)
    d.box(660,330,350,75,"Remote model provider",size=24)
    d.line([(835,280),(835,330)])
    d.box(30,350,430,95,"Save source observation",["Success or safe source failure", "Earlier evidence remains available"],TEAL,TEAL_LINE,size=24)
    d.line([(245,280),(245,350)])
    d.line([(1010,367),(1070,367),(1070,160),(935,160),(935,190)],dashed=True)
    d.box(620,480,430,90,"Native answer or HTTP error",["Transport status is separate"],BLUE,BLUE_LINE,size=24)
    d.line([(620,235),(550,235),(550,525),(620,525)])
    d.box(30,525,430,95,"Private domain record",["Finalized outcome or not_finalized"],TEAL,TEAL_LINE,size=24)
    d.line([(245,445),(245,525)])
    d.text(540,685,"Client timeout does not guarantee native or remote cancellation",23,600,color=AMBER_LINE)
    return d.save("05_failure_boundaries")



def result_delivery():
    d = Diagram(720)
    d.text(30,35,"Native A2A delivery",28,600,anchor="start")
    d.box(250,80,580,80,"LSCore native A2A task",["Answer text and native task status"],BLUE,BLUE_LINE)
    d.line([(540,160),(540,210)])
    d.box(250,210,580,85,"MAS A2A node and workflow",["Returns answer text and transport success"],GRAY)
    d.line([(540,295),(540,342)])
    d.box(250,342,580,70,"User receives prose",["A2A completed can describe partial evidence"],GRAY,size=24)
    d.text(540,468,"No automatic typed ATI result or domain outcome transfer",24,600,color=AMBER_LINE)
    d.text(30,535,"Separate domain evidence export",28,600,anchor="start")
    d.box(25,580,300,95,"ATI domain store",["Private observations", "and finalized assessment"],TEAL,TEAL_LINE,size=24)
    d.box(395,580,300,95,"Headless client",["Reads saved assessment"],TEAL,TEAL_LINE,size=24)
    d.box(765,580,290,95,"Private JSON file",["Not an A2A DataPart"],TEAL,TEAL_LINE,size=24)
    d.line([(325,627),(395,627)])
    d.line([(695,627),(765,627)])
    return d.save("06_native_result_delivery")



def set_cell_shading(cell, fill):
    properties = cell._tc.get_or_add_tcPr()
    item = OxmlElement("w:shd")
    item.set(qn("w:fill"), fill)
    properties.append(item)


def add_hyperlink(paragraph, text, url):
    from docx.opc.constants import RELATIONSHIP_TYPE
    rel = paragraph.part.relate_to(url, RELATIONSHIP_TYPE.HYPERLINK, is_external=True)
    hyperlink = OxmlElement("w:hyperlink")
    hyperlink.set(qn("r:id"), rel)
    run = OxmlElement("w:r")
    props = OxmlElement("w:rPr")
    color = OxmlElement("w:color")
    color.set(qn("w:val"), "245786")
    props.append(color)
    run.append(props)
    item = OxmlElement("w:t")
    item.text = text
    run.append(item)
    hyperlink.append(run)
    paragraph._p.append(hyperlink)


def paragraph(doc, text, *, style=None, bold_prefix=None):
    p = doc.add_paragraph(style=style)
    if bold_prefix and text.startswith(bold_prefix):
        p.add_run(bold_prefix).bold = True
        p.add_run(text[len(bold_prefix):])
    else:
        p.add_run(text)
    return p


def figure(doc, filename, caption, alt, width=6.9):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(5)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.keep_with_next = True
    shape = p.add_run().add_picture(str(ASSETS / filename), width=Inches(width))
    shape._inline.docPr.set("descr", alt)
    p = paragraph(doc, caption, style="Caption")
    p.paragraph_format.keep_with_next = False


def table(doc, headers, rows, widths):
    t = doc.add_table(rows=1, cols=len(headers))
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    t.autofit = False
    for col, width in zip(t.columns, widths, strict=True):
        col.width = Inches(width)
    border = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        item = OxmlElement(f"w:{edge}")
        for key, value in (("val", "single"), ("sz", "5"), ("color", "D9D9D9")):
            item.set(qn(f"w:{key}"), value)
        border.append(item)
    t._tbl.tblPr.append(border)
    margin = OxmlElement("w:tblCellMar")
    for side, value in (("top", "90"), ("bottom", "90"), ("left", "110"), ("right", "110")):
        item = OxmlElement(f"w:{side}")
        item.set(qn("w:w"), value)
        item.set(qn("w:type"), "dxa")
        margin.append(item)
    t._tbl.tblPr.append(margin)
    for i, title in enumerate(headers):
        t.rows[0].cells[i].text = title
        set_cell_shading(t.rows[0].cells[i], "E7EFF7")
        for run in t.rows[0].cells[i].paragraphs[0].runs:
            run.bold = True
    repeat = OxmlElement("w:tblHeader")
    t.rows[0]._tr.get_or_add_trPr().append(repeat)
    for idx, row in enumerate(rows):
        cells = t.add_row().cells
        for i, value in enumerate(row):
            cells[i].text = value
            if idx % 2:
                set_cell_shading(cells[i], "F7F9FB")
    for row in t.rows:
        for cell, width in zip(row.cells, widths, strict=True):
            cell.width = Inches(width)
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            for p in cell.paragraphs:
                p.paragraph_format.space_after = Pt(1)
                p.paragraph_format.line_spacing = 1.05
                for r in p.runs:
                    r.font.size = Pt(10.5)
    paragraph(doc, "", style="Source")
    return t


def sources(doc, text):
    return paragraph(doc, "Evidence  " + text, style="Source")


def page(doc, heading):
    doc.add_page_break()
    doc.add_heading(heading, level=1)


def build_doc():
    doc = Document()
    section = doc.sections[0]
    section.page_width = Inches(8.5)
    section.page_height = Inches(11)
    section.top_margin = Inches(0.65)
    section.bottom_margin = Inches(0.65)
    section.left_margin = Inches(0.7)
    section.right_margin = Inches(0.7)
    section.footer_distance = Inches(0.28)
    styles = doc.styles
    for name in ("Normal", "Title", "Subtitle", "Heading 1", "Heading 2", "Caption"):
        style = styles[name]
        style.font.name = "Liberation Sans"
        style.font.color.rgb = RGBColor(0, 0, 0)
        style.paragraph_format.space_after = Pt(7)
    styles["Normal"].font.size = Pt(11)
    styles["Normal"].paragraph_format.line_spacing = 1.12
    styles["Title"].font.size = Pt(28)
    styles["Title"].font.bold = True
    styles["Title"].paragraph_format.space_after = Pt(5)
    styles["Subtitle"].font.size = Pt(11)
    styles["Subtitle"].font.italic = False
    styles["Heading 1"].font.size = Pt(21)
    styles["Heading 1"].font.bold = True
    styles["Heading 1"].paragraph_format.space_before = Pt(0)
    styles["Caption"].font.size = Pt(9.5)
    styles["Caption"].font.italic = False
    styles["Caption"].paragraph_format.space_after = Pt(8)
    source = styles.add_style("Source", 1)
    source.font.name = "Liberation Sans"
    source.font.size = Pt(9)
    source.font.color.rgb = RGBColor.from_string("46515D")
    source.paragraph_format.space_after = Pt(5)
    source.paragraph_format.line_spacing = 1.05
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    footer.add_run("ATI and LSCore   |   ").font.size = Pt(9)
    field = OxmlElement("w:fldSimple")
    field.set(qn("w:instr"), "PAGE")
    footer._p.append(field)
    doc.core_properties.title = "ATI native LSCore integration visual guide"
    doc.core_properties.subject = "Execution ownership evidence and downstream integration"
    doc.core_properties.author = ""
    doc.core_properties.keywords = "ATI, LSCore, A2A, MAS, APPENG-7003"

    doc.add_paragraph("ATI native LSCore integration", style="Title")
    doc.add_paragraph("Visual guide to native integration   |   25 November 2026", style="Subtitle")
    paragraph(doc, "Lightspeed Core (LSCore) runs the ATI agent. It owns model calls, tool scheduling, retries and native A2A delivery. Actionable Threat Intelligence (ATI) supplies read-only MCP tools for source evidence, private records and provisional priority. MAS delegates assessment requests to native LSCore.")
    figure(doc, "01_native_architecture.png", "Figure 1  Native LSCore owns execution. Blue is LSCore; green is ATI domain code.", "Clients and MAS call native LSCore. Its embedded OGX calls the model and ATI MCP tools. ATI reads sources and stores private evidence without a model client.", width=6.7)
    paragraph(doc, "MAS is the multi-agent system that delegates work. A2A is the agent-to-agent protocol. MCP exposes callable tools and data. OGX is embedded inside the tested LSCore process; it is not a required separate service.")
    paragraph(doc, "We used upstream main pinned to commit 7693565545044173814b1c5ad5aa66dd329e8b34, reporting LSCore 0.8.0rc1 with OGX 1.2.5. This is a frozen source snapshot, not a moving main branch or a validated stable release.")
    sources(doc, "baseline.json; REPORT.md; ../../README.md. LSCore executes the agent; Lightspeed MCP is a separate customer fleet data source.")

    page(doc, "How the native LSCore loop behaves")
    paragraph(doc, "The model asks for tools, OGX executes them, and results return to the model. Prompts, profiles and skills customize instructions. No documented extension was found for our Python code to choose conditional edges between native loop steps.")
    figure(doc, "02_native_loop.png", "Figure 2  Observed control flow and retry boundary in the pinned backend.", "The native wrapper invokes an OGX response. Independent read A and read B run sequentially. An outer retry can begin another response with fresh allowances.", width=6.55)
    table(doc, ["Check", "Observed result"], [
        ("Concurrency", "Two independent 0.7-second reads ran sequentially, about 1.72 seconds overall. Separate requests overlapped."),
        ("Run limits", "Four model rounds became eight model calls and eight tool executions after an outer retry reset the allowances."),
        ("Timeout", "A configured 1-second MCP timeout did not stop a 1.2-second tool. The setting was documented as reserved."),
    ], [1.25,5.65])
    paragraph(doc, "Native LSCore schedules the tools and applies per-response limits. An aggregate investigation budget and parallel tool scheduling remain documented framework gaps.")
    sources(doc, "results/concurrency-origins.json; results/limits-origins.json; results/deadline-probe.json; FRAMEWORK_GAPS.md.")

    page(doc, "How ATI domain tools support the native loop")
    paragraph(doc, "The headless client pre-registers one CVE and environment. Native LSCore then calls collect_cve_source separately for each source. For a free-form A2A request, the native agent can first call begin_cve_assessment. ATI tools never call a model or run an agent loop.")
    figure(doc, "03_domain_tools_sequence.png", "Figure 3  One source call followed by domain finalization. LSCore chooses when to repeat collection.", "Native LSCore asks one domain collector to run. The tool reserves its scoped observation, reads the source, saves evidence and returns selected facts. A later native tool call computes priority from the saved records.",width=6.65)
    paragraph(doc, "Repeated collection of the same source in one assessment reuses its observation, including failure. Finalization reads the recorded evidence; the model cannot provide invented affected counts or risk inputs. Finalizing before all sources are available produces incomplete evidence.")
    paragraph(doc, "The structured record is business data, not LSCore task state. If native execution stops before finalization, observations survive but the assessment remains not_finalized. Begin a fresh assessment to refresh sources.")
    sources(doc, "../../src/ati_lscore/domain.py; records.py; mcp_server.py; ../../verification.json.")

    page(doc, "How Journey 01 assesses a CVE")
    paragraph(doc, "The headless command submits one native LSCore query per CVE. It reports native request status separately from the finalized domain outcome.")
    figure(doc, "04_journey_assessment.png", "Figure 4  Six collector operations; both Lightspeed operations use the same MCP connection.", "Native LSCore calls six collectors and finalizes the evidence. The CVE and fleet collectors share Lightspeed MCP. Threat intelligence reads public HTTP feeds. Native answer text and private domain JSON are separate outputs.",width=6.35)
    paragraph(doc, "Collector means a named fetch operation. The four core source families are Security Data, OSIDB, Lightspeed MCP and Support MCP. Fleet inspection reuses Lightspeed. Threat intelligence adds public feeds: FIRST EPSS probability scores, CISA exploitation assessments in CVE.org records, and CISA's known-exploited catalog.")
    paragraph(doc, "Default priority: confirmed affected systems plus either reported public exploit availability or observed exploitation means urgent review. A complete zero lookup means no affected systems reported; otherwise needs review. EPSS supports context; the manual-review policy always requests review.",bold_prefix="Default priority:")
    paragraph(doc, "OSIDB is Red Hat's flaw database. Collection is bounded to ten hosts, two CVE pages and five Support hits. A collector defaults to 35 seconds; the 240-second client timeout limits waiting only.")
    paragraph(doc, "The older Support MCP is accepted for this PoC. Errata enrichment, remediation, downtime estimates and post-change verification are outside scope.")
    sources(doc, "../../JOURNEY01.md; verification.json; src/ati_lscore/assessment.py.")

    page(doc, "Where evidence and failure boundaries remain")
    paragraph(doc, "ATI saves source observations independently of the model answer. A source failure is returned as safe domain data, retaining earlier successful evidence. Model errors, hidden provider retries and native loop cancellation remain LSCore dependency concerns.")
    figure(doc, "05_failure_boundaries.png", "Figure 5  Domain evidence survives separately from native request success or failure.", "Native LSCore controls model inference and calls ATI tools. The tool saves source success or failure in a private record. Native model replies or errors are a separate path and do not establish completed domain evidence.",width=6.75)
    paragraph(doc, "Native per-response limits are not a demonstrated whole-investigation budget. One source call can also make multiple bounded network calls. Local cancellation does not guarantee that a remote source or model stopped working.")
    p=paragraph(doc, "The lost tool-error text in pinned OGX 1.2.5 was already fixed upstream by ")
    add_hyperlink(p,"merged PR 6745","https://github.com/ogx-ai/ogx/pull/6745")
    p.add_run(" on 13 October 2026. A compatible fixed package or backport and native-path retest remain pending. This is a version issue, not a permanent architectural limitation. No dependency upgrade or local upstream patch was applied.")
    sources(doc, "results/error-origins.json; results/upstream-status.json; ../../verification.json.")

    page(doc, "How native results reach MAS and clients")
    paragraph(doc, "The pinned native A2A endpoint returns answer text. It does not emit ATI's typed JSON record or map the domain outcome into task status. The headless client exports the saved domain record separately.")
    figure(doc, "06_native_result_delivery.png", "Figure 6  Native prose delivery and explicit local evidence export remain separate.", "LSCore sends native task status and answer text to MAS. Typed ATI records are exported independently from the domain store by the headless client. No automatic structured A2A bridge is implemented.",width=6.55)
    table(doc,["Verification","Observed native behavior"],[
        ("Real model synthetic sources","Six collectors and finalization completed; the synthetic positive case returned provisional urgent_review."),
        ("Real model real sources","Five collectors succeeded and Support failed. Native query completed; the domain outcome correctly stayed partial."),
        ("Native A2A and MAS","A2A returned completed with text only. The local MAS workflow completed when reporting the existing finalized record; source collection was not repeated."),
    ],[1.6,5.3])
    paragraph(doc,"The current native A2A gap is explicit: transport success is not complete evidence. Durable recovery, production deployment and positive live fleet coverage remain unverified. LangGraph is future comparison work, not a second implementation shipped here.")
    sources(doc,"../../verification.json; MAS_INTEGRATION.md; results/structured-contract.json.")
    for root in (doc.styles.element,doc.element):
        for border in root.xpath(".//w:pBdr"):
            border.getparent().remove(border)
    doc.save(OUT)
    return OUT



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", required=True, type=Path)
    args = parser.parse_args()
    ASSETS.mkdir(parents=True, exist_ok=True)
    inputs = [architecture(), native_loop(), domain_sequence(), journey(),
              failure_boundaries(), result_delivery()]
    renderer = HERE / "render_diagrams.cjs"
    renderer.write_text(
        "const sharp=require(process.argv[2]);\n"
        "const paths=JSON.parse(process.argv[3]);\n"
        "(async()=>{for(const p of paths){await sharp(p,{density:240})"
        ".resize({width:2700}).png().toFile(p.replace(/\\.svg$/,'.png'));}})()"
        ".catch(e=>{console.error(e.message);process.exit(1)});\n"
    )
    subprocess.run([
        str(args.runtime_root / "node/bin/node"), str(renderer),
        str(args.runtime_root / "node/node_modules/sharp"), json.dumps([str(p) for p in inputs]),
    ], check=True)
    print(build_doc())


if __name__ == "__main__":
    main()
