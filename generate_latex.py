from glob import glob
import json
import os
import base64

latex = ""
report_id = ""
report_name = ""
#read template
ltemplate = open("./template.tex", "r")
latex = ltemplate.read()

def saveFile(report_id, data, name, type):
    if name:
        filename = "output/" + report_id + "/images/" + name
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        z = open(filename, "wb")
        x = data.split(",")
        z.write(base64.b64decode(x[1]))
        z.close()
        return True

def saveLogo(report_id, logo, logo_name, logo_type):
    if logo:
        if logo_type == "image/png" or logo_type == "image/jpg" or logo_type == "image/jpeg":
            filename = "output/" + report_id + "/" + logo_name
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            z = open(filename, "wb")
            x = logo.split(",")
            z.write(base64.b64decode(x[1]))
            z.close()
            return True

def saveOutput(report_id, report_name, latex):
    if report_id != "":
        filename = "output/" + report_id + "/" + report_name + ".tex"
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        z = open(filename, "w")
        z.write(latex)
        z.close()
        print("Done. Check /output/" + report_id + "/")
        quit()
    else:
        print("Put VULNREPO json file to /input/")
        quit()

def lenSeverity(severity: str, listobj):
    return str(len(list(filter(lambda z: z['severity'] == severity, listobj))))

def prepchars(input):
    input = input.replace("$", "\$")
    input = input.replace("&", "\&")
    input = input.replace("%", "\%")
    input = input.replace("{", "\{")
    input = input.replace("_", "\_")
    input = input.replace("#", "\#")
    input = input.replace("}", "\}")
    input = input.replace("^", "")
    return input

if latex != "":
    for f_name in glob('input/*.json'):
        f = open(f_name, "r")
        data = json.load(f)

        if data['report_name']:
            latex = latex.replace("&report_name;", data['report_name'])
            report_name = data['report_name']
        else:
            latex = latex.replace("&report_name;", "")    

        if data['report_scope']:
            latex = latex.replace("&report_scope;", data['report_scope'])
        else:
            latex = latex.replace("&report_scope;", "")

        if data['report_id']:
            latex = latex.replace("&report_id;", data['report_id'])
            report_id = data['report_id']
        else:
            latex = latex.replace("&report_id;", "")    

        if data['report_version']:
            latex = latex.replace("&report_version;", str(data['report_version']))
        else:
            latex = latex.replace("&report_version;", "")

        if 'logo_name' in data['report_settings']['report_logo']:
            if saveLogo(data['report_id'], data['report_settings']['report_logo']['logo'], data['report_settings']['report_logo']['logo_name'], data['report_settings']['report_logo']['logo_type']):
                if data['report_settings']['report_logo']['logo_type'] == "image/png" or data['report_settings']['report_logo']['logo_type'] == "image/jpg" or data['report_settings']['report_logo']['logo_type'] == "image/jpeg":
                    logos = """
\\begin{figure}[h]
\includegraphics[width="""+str(data['report_settings']['report_logo']['width'])+"""px, height="""+str(data['report_settings']['report_logo']['height'])+"""px]{"""+data['report_settings']['report_logo']['logo_name']+"""}
\centering
\end{figure}
                    """
                    latex = latex.replace("&report_logo;", logos)
        else:
            print('Key logo name not found, old report version, add logo manually :-(')
            latex = latex.replace("&report_logo;", "")




        # stats table
        latex = latex.replace("&critical_len;", lenSeverity('Critical', data['report_vulns']))
        latex = latex.replace("&high_len;", lenSeverity('High', data['report_vulns']))
        latex = latex.replace("&medium_len;", lenSeverity('Medium', data['report_vulns']))
        latex = latex.replace("&low_len;", lenSeverity('Low', data['report_vulns']))
        latex = latex.replace("&info_len;", lenSeverity('Info', data['report_vulns']))
        latex = latex.replace("&severity_total;", str(len(data['report_vulns'])))

        issues = ""
        reft = ""
        for a in data['report_vulns']:
            
            des = ''.join(a['desc'])
            des = des.replace("_", "-")
            des = prepchars(des)
            pocc = ''.join(a['poc'])
            pocc = pocc.replace("_", "-")
            pocc = pocc.replace("\n", "\\\\")
            pocc = pocc.replace("\r\n", "\\\\")
            pocc = prepchars(pocc)
            ref1 = a['ref']

            if len(ref1) > 0:
                try:
                    el = ref1.split('\n')
                except AttributeError:
                    el = ref1[0].split('\n')
                    pass

                for refx in el:
                    if refx != '':
                        reft = reft + "\\url{"+refx+"}\\\\"
            else:
                reft = ""

            issues = issues + """
\subsection{"""+a['title']+"""}

\\textbf{Severity:} """+a['severity']+"""\\\\\\\\
\\textbf{Description:}\\\\
"""+str(des)+"""\\\\\\\\
\\textbf{PoC:}\\\\
\\seqsplit{"""+str(pocc)+"""}\\\\\\\\
\\textbf{References:}\\\\
"""+str(reft)+"""\\\\\\\\
            """

            atfile = ""
            for b in a['files']:

                if saveFile(report_id, b['data'], b['title'], b['type']):
                    title = b['title'].replace("_", "-")
                    atfile = atfile + """
\\begin{figure}
\includegraphics[width=\\textwidth, height=500px]{images/"""+b['title']+"""}
\centering
\\textbf{"""+title+"""} ("""+str(b['size'])+""" bytes)\\\\ 
\\textbf{sha256:} """+b['sha256checksum']+"""
\end{figure}
                    """
            issues = issues + atfile
        # Closing file
        f.close()
        latex = latex.replace("&report_issues;", issues)

        for researcher in data['researcher']:
            if researcher['reportername']:
                latex = latex.replace("&researcher;", researcher['reportername'])
            else:
                latex = latex.replace("&researcher;", "")


saveOutput(report_id, report_name, latex)