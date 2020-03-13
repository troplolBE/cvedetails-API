from bs4 import BeautifulSoup

import urllib2
import csv
import re
import argparse
import pandas

url = 'http://www.cvedetails.com/vulnerability-list/vendor_id-{vid}/product_id-{pid}/version_id-{verid}/'

hdr = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
    'Accept-Encoding': 'none',
    'Accept-Language': 'en-US,en;q=0.8',
    'Connection': 'keep-alive'}

headers = ["#", "CVE ID", "CWE ID", "# of Exploits", "Type", "Publish Date", "Update Date", "Score", "Gained Access", "Access", "Complexity", "Authentication", "Conf.", "Integ.", "Avail.", "version-id", "Description"]

def get_cves_from_page(url, filename, version):
    req = urllib2.Request(url, None, hdr)
    http = urllib2.urlopen(req)
    if http.getcode() != 200:
        print('[!] Error, webrequest failed. Be sure that th ids you gave are correct.')
        exit(1)
    html = http.read()
    soup = BeautifulSoup(html, 'html.parser')
    table = soup.find('table', attrs={'id': 'vulnslisttable'})
    result = [[td.text.encode("utf-8") for td in row.find_all("td")] for row in table.select("tr + tr")]
    [result[x].append(version) for x in range(0, len(result), 2)]
    results = []
    for x in range(0, len(result), 2):
        results.append(result[x] + result[x + 1])
    results = [map(str.strip, td) for td in results]

    with open(filename, "a") as f:
        wr = csv.writer(f)
        wr.writerows(results)
        return results

def get_links(url):
    req = urllib2.Request(url, None, hdr)
    http = urllib2.urlopen(req)
    html = http.read()
    soup = BeautifulSoup(html, 'html.parser')
    links = []
    for a in soup.find_all('a', attrs={'href': re.compile("^/vulnerability-list"), 'title': re.compile("^Go")}):
        links.append("https://www.cvedetails.com" + a['href'])
    return links

def write_headers(filename):
    with open(filename, "w") as f:
        wr = csv.writer(f)
        wr.writerow(headers)

def get_cves(vendor, product, version):
    print('[*] Retrieving cves from version {}'.format(version))
    filename = "{name}.csv".format(name = vendor + product + version)
    write_headers(filename)
    links = get_links(url.format(vid = vendor, pid = product, verid = version))
    cves = []
    print('[*] Writing cves to file {}'.format(filename))
    for link in links:
        cves.extend(get_cves_from_page(link, filename, version))
    return cves

#------------------------------------------------------------------------------
# Command-line parsing
#------------------------------------------------------------------------------
parser = argparse.ArgumentParser()

parser.add_argument('--vendor',
                    help="Vendor (required)",
                    action='store',
                    required=True,
                    dest='vendor')
parser.add_argument('--product',
                    help='Product (required)',
                    action='store',
                    required=True,
                    dest='product')
parser.add_argument('--version',
                    help='Version (required)',
                    action='store',
                    required=True,
                    dest='version')
parser.add_argument('--upgrade',
                    help="Newer version of product (required)",
                    action='store',
                    required=True,
                    dest='upgrade')
parser.add_argument('--excel',
                    help='Nam of the excel file (required)',
                    action='store',
                    required=True,
                    dest='excel')

args = parser.parse_args()

#------------------------------------------------------------------------------
# Retrieving data from website
#------------------------------------------------------------------------------
old = get_cves(args.vendor, args.product, args.version)
upgrade = get_cves(args.vendor, args.product, args.upgrade)

#------------------------------------------------------------------------------
# Data processing
#------------------------------------------------------------------------------
print('[*] Processing data...')
unpatched = []
patched = []

for cve in old:
    if cve not in upgrade:
        patched.append(cve)
    elif cve in upgrade:
        unpatched.append(cve)

for cve in upgrade:
    if cve not in unpatched:
        unpatched.append(cve)

#------------------------------------------------------------------------------
# Save in excel
#------------------------------------------------------------------------------

print('[*] Saving in excel...')
excelfile = pandas.ExcelWriter('{}.xlsx'.format(args.excel))

dfold = pandas.read_csv('{}.csv'.format(args.vendor + args.product + args.version))
dfnew = pandas.read_csv('{}.csv'.format(args.vendor + args.product + args.upgrade))

dfold.to_excel(excelfile, sheet_name='CVEs old version')
dfnew.to_excel(excelfile, sheet_name='CVEs new version')

dfunpat = pandas.DataFrame(unpatched, columns=headers)
dfpat = pandas.DataFrame(patched, columns=headers)

dfunpat.to_excel(excelfile, sheet_name='Unpatched CVEs')
dfpat.to_excel(excelfile, sheet_name='Patched CVEs')

print('[*] Saving file {}.xlsx'.format(args.excel))
excelfile.save()

