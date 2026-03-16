import nmap
import re
import os
import json
def is_root():
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False
#---------------------------------------------------------------------------------------------------------------------
#To EXTRACT CVE{IF datectable by NMAP-vuln SCRIPT}
def cve_extract(services1):
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    cve = set()
    if 'script' in services1:
        for script_name, output in services1['script'].items():
            cve.update(cve_pattern.findall(output))

    return list(cve) if cve else None
#---------------------------------------------------------------------------------------------------------------------
#TAKE INPUT IPs OR DOMAIN NAME OR IP RANGE OR CIDR


def input_():
    input_ips=input("Enter RHOSTS seperated by (comma[,] or space[ ]): ").strip()
    if input_ips=='' or input_ips=='\n':
        print("NO IP Detected")
        print("scanning default IP:45.33.32.156")
        return ['45.33.32.156']
    
    return [ip.strip() for ip in input_ips.replace(",", " ").split() if ip.strip()]  


#---------------------------------------------------------------------------------------------------------------------
#TAKE ARGUMENTS


def scanning_arguments_():
    df_arguments= "-sV -T4 -D RND:10 -p- --open --script=vuln,default,safe --min-rate=5000"
    print("DEFAULT ARGUMENTS:-sV -T4 -D RND:10 -p- --open --script=vuln,default,safe --min-rate=5000")
    ag=input("Enter Arguments or press ENTER: ")
    if not ag:
      if not is_root():
          return "--unprivileged "+df_arguments
      else:
          return df_arguments
          
          
    return ag
#---------------------------------------------------------------------------------------------------------------------


                    #------------------------------------------------------------#
                               #PYTHON-NMAP SCANNING & O/P Structuring#

def scanning_(scanner,tg,structured_output):
    
    ag=scanning_arguments_()
    try: 
        print("Scanning...........")
        scanner.scan(hosts=" ".join(tg),arguments=ag)    
    except Exception as e:
        print(f"[!] Scan failed: {e}")
        return
    for host in scanner.all_hosts():


        print(f'\n[*]Scanning Host:{host} ')
        for protocols in scanner[host].all_protocols() :
       
         ports=scanner[host][protocols].keys()
         for port in ports :
           services=scanner[host][protocols][port]
           os1=scanner[host].get('osmatch', [])
           os1=os1[0]['name'] if os1 else None
           if scanner[host].state() !='down':
               structured_output.append({
               'host':host,
               'protocol':protocols,
               'port': port,
               'state':scanner[host].state(),
               'service_product':scanner[host][protocols][port].get('name', None),
               'service':scanner[host][protocols][port].get('product', None),
               'version': scanner[host][protocols][port].get('version', None),
               'os': os1,
               'cve':cve_extract(services)
                }) 
               print(f'\n[*]Protocol :{protocols}  Port :{port}  Service Runnung :{scanner[host][protocols][port]['product']}  version :{scanner[host][protocols][port]['version']}  OS :{os1}  CVE Found :{cve_extract(services)}  state:{scanner[host].state()}')
    print(f"[+] Finished scanning {tg}, found {len(structured_output)} service entries.\n")       
#---------------------------------------------------------------------------------------------------------------------

def html_summary(structured_output):
        
    html = """
    <html>
    <head>
        <title>Nmap Scan Summary</title>
        <style>
            body { font-family: Arial; padding: 20px; background: #f9f9f9; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            tr:nth-child(even) { background-color: #f9f9f9; }
            .cve-count { font-weight: bold; color: red; }
            .no-cve { color: green; font-weight: bold; }
        </style>
    </head>
    <body>
        <h2>Nmap Scan Report Summary</h2>
        <table>
            <tr>
                <th>Host</th>
                <th>Port</th>
                <th>Protocol</th>
                <th>Service</th>
                <th>Version</th>
                <th>OS</th>
                <th>State</th>
                <th>CVE Count</th>
            </tr>
    """

    for entry in structured_output:
        cves = entry.get('cve', [])
        html += f"""
            <tr>
                <td>{entry['host']}</td>
                <td>{entry['port']}</td>
                <td>{entry['protocol']}</td>
                <td>{entry['service'] or 'N/A'}</td>
                <td>{entry['version'] or 'N/A'}</td>
                <td>{entry['os'] or 'Unknown'}</td>
                <td>{entry['state']}</td>
                <td>{'<span class="cve-count">' + str(len(cves)) + '</span>' if cves else '<span class="no-cve">0</span>'}</td>
            </tr>
        """

    html += """
        </table>
        <p>Generated by Python-Nmap Scanner</p>
    </body>
    </html>
    """

    with open("scan_summary.html", "w", encoding="utf-8") as f:
        f.write(html)

def main():
    print('\n\t\t[!]DISCLAMER: Do NOT SCAN any HOST without PERMISSION[!]\n\t\t\tDEFAULT: 45.33.32.156 or scanme.nmap.org\n\t\t\t  Change arguments as per requirements\n')
    structured_output=[]
    targets=input_()
    try:
        sc = nmap.PortScanner()
    except nmap.PortScannerError as e:
        print(f"[!] Nmap error: {e}")
        return
   
    scanning_(sc,targets,structured_output)
    with open("scan_results.json", "w") as f:
        json.dump(structured_output, f, indent=4)
    html_summary(structured_output)    

if __name__=='__main__':
    main()






