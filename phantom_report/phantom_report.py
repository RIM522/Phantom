import json
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, white, black
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.units import inch
from datetime import datetime

class PhantomReport:
    def __init__(self):
        self.output_file = "phantom_report.pdf"
        self.colors = {
            'purple': HexColor('#8b00ff'),
            'red': HexColor('#ff0040'),
            'blue': HexColor('#00aaff'),
            'dark': HexColor('#0a0a0a'),
            'gray': HexColor('#333333'),
            'light_gray': HexColor('#888888'),
            'green': HexColor('#00ff88'),
            'orange': HexColor('#ff6600'),
        }

    def load_data(self):
        try:
            with open('../phantom_red/scan_results.json') as f:
                self.scan = json.load(f)
        except:
            self.scan = {}
        try:
            with open('../phantom_intel/intel_results.json') as f:
                self.intel = json.load(f)
        except:
            self.intel = {}
        try:
            with open('../phantom_blue/blue_alerts.json') as f:
                self.alerts = json.load(f)
        except:
            self.alerts = []
        try:
            with open('../phantom_map/kill_chain.json') as f:
                self.kill_chain = json.load(f)
        except:
            self.kill_chain = []
        try:
            with open('../phantom_score/score_results.json') as f:
                self.score = json.load(f)
        except:
            self.score = {}
        try:
            with open('../phantom_ai/ai_analysis.json') as f:
                self.ai = json.load(f)
        except:
            self.ai = {}

    def build_styles(self):
        styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle(
            'Title', fontSize=24, textColor=self.colors['purple'],
            spaceAfter=10, fontName='Helvetica-Bold'
        )
        self.heading_style = ParagraphStyle(
            'Heading', fontSize=14, textColor=self.colors['purple'],
            spaceAfter=8, fontName='Helvetica-Bold'
        )
        self.normal_style = ParagraphStyle(
            'Normal', fontSize=10, textColor=black,
            spaceAfter=6, fontName='Helvetica'
        )
        self.red_style = ParagraphStyle(
            'Red', fontSize=10, textColor=self.colors['red'],
            spaceAfter=6, fontName='Helvetica-Bold'
        )
        self.blue_style = ParagraphStyle(
            'Blue', fontSize=10, textColor=self.colors['blue'],
            spaceAfter=6, fontName='Helvetica'
        )

    def generate(self):
        doc = SimpleDocTemplate(
            self.output_file,
            pagesize=letter,
            rightMargin=inch,
            leftMargin=inch,
            topMargin=inch,
            bottomMargin=inch
        )

        story = []

        # Header
        story.append(Paragraph("👻 PHANTOM", self.title_style))
        story.append(Paragraph("Real-time Attack Simulation & Defense Intelligence", self.normal_style))
        story.append(Paragraph("SECURITY INCIDENT REPORT", self.heading_style))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.normal_style))
        story.append(HRFlowable(width="100%", thickness=2, color=self.colors['purple']))
        story.append(Spacer(1, 0.2*inch))

        # Score global
        story.append(Paragraph("1. SECURITY SCORE", self.heading_style))
        score_data = [
            ['Metric', 'Score', 'Status'],
            ['Global Security Score', str(self.score.get('total_score', 'N/A')) + '/100', self.score.get('level', 'N/A')],
            ['Total Alerts', str(len(self.alerts)), ''],
            ['Kill Chain Steps', str(len(self.kill_chain)), ''],
        ]
        score_table = Table(score_data, colWidths=[3*inch, 2*inch, 2*inch])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), self.colors['purple']),
            ('TEXTCOLOR', (0,0), (-1,0), white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, self.colors['gray']),
            ('FONTSIZE', (0,0), (-1,-1), 10),
            ('PADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 0.2*inch))

        # Ports découverts
        story.append(Paragraph("2. DISCOVERED PORTS & SERVICES", self.heading_style))
        port_data = [['Port', 'Service', 'Version', 'Status']]
        for host, data in self.scan.items():
            for port in data.get('ports', []):
                port_data.append([
                    str(port['port']),
                    port['service'],
                    port['version'][:20] if port['version'] else 'N/A',
                    'OPEN'
                ])
        if len(port_data) > 1:
            port_table = Table(port_data, colWidths=[1*inch, 1.5*inch, 3*inch, 1*inch])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), self.colors['blue']),
                ('TEXTCOLOR', (0,0), (-1,0), white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 0.5, self.colors['gray']),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('PADDING', (0,0), (-1,-1), 6),
                ('TEXTCOLOR', (-1,1), (-1,-1), self.colors['red']),
            ]))
            story.append(port_table)
        story.append(Spacer(1, 0.2*inch))

        # CVEs critiques
        story.append(Paragraph("3. CRITICAL VULNERABILITIES (CVE)", self.heading_style))
        cve_data = [['CVE ID', 'Severity', 'Service', 'Description']]
        for host, services in self.intel.items():
            for service in services:
                for cve in service.get('cves', []):
                    if cve.get('severity') in ['CRITICAL', 'HIGH']:
                        cve_data.append([
                            cve['id'],
                            cve['severity'],
                            service['service'] + ' ' + service['version'],
                            cve['description'][:50] + '...'
                        ])
        if len(cve_data) > 1:
            cve_table = Table(cve_data, colWidths=[1.5*inch, 1*inch, 1.5*inch, 2.5*inch])
            cve_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), self.colors['red']),
                ('TEXTCOLOR', (0,0), (-1,0), white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 0.5, self.colors['gray']),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('PADDING', (0,0), (-1,-1), 5),
            ]))
            story.append(cve_table)
        story.append(Spacer(1, 0.2*inch))

        # Kill Chain
        story.append(Paragraph("4. MITRE ATT&CK KILL CHAIN", self.heading_style))
        for technique in self.kill_chain:
            story.append(Paragraph(
                f"• {technique['id']} — {technique['name']} [{technique['tactic'].upper()}] — {technique.get('severity', '')}",
                self.normal_style
            ))
        story.append(Spacer(1, 0.2*inch))

        # Alertes Blue Team
        story.append(Paragraph("5. BLUE TEAM ALERTS", self.heading_style))
        for alert in self.alerts:
            story.append(Paragraph(
                f"• {alert.get('severity', '')} | {alert.get('message', '')} | {alert.get('src_ip', '')} → {alert.get('dst_ip', '')} | {alert.get('mitre', '')}",
                self.normal_style
            ))
        story.append(Spacer(1, 0.2*inch))

        # AI Analysis
        story.append(Paragraph("6. AI ANALYST REPORT", self.heading_style))
        ai_text = self.ai.get('analysis', 'No AI analysis available')
        for line in ai_text.split('\n'):
            if line.strip():
                story.append(Paragraph(line.strip(), self.normal_style))
        story.append(Spacer(1, 0.2*inch))

        # Footer
        story.append(HRFlowable(width="100%", thickness=1, color=self.colors['purple']))
        story.append(Paragraph("👻 PHANTOM — Confidential Security Report", self.normal_style))

        doc.build(story)
        print(f"[📄 PHANTOM REPORT] Rapport généré : {self.output_file}")

if __name__ == "__main__":
    report = PhantomReport()
    report.load_data()
    report.build_styles()
    report.generate()
