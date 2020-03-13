from bs4 import BeautifulSoup

import urllib2
import csv
import re
import argparse

url = 'http://www.cvedetails.com/vulnerability-list/vendor_id-{vid}/product_id-{pid}/version_id-{verid}/'

hdr = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
    'Accept-Encoding': 'none',
    'Accept-Language': 'en-US,en;q=0.8',
    'Connection': 'keep-alive'}

headers = ["#", "CVE ID", "CWE ID", "# of Exploits", "Type", "Publish Date", "Update Date", "Score", "Gained Access", "Access", "Complexity", "Authentication", "Conf.", "Integ.", "Avail.", "Description"]

def get_cves_from_page(url, filename):
    req = urllib2.Request(url, None, hdr)
    http = urllib2.urlopen(req)
    if http.getcode() != 200:
        print('[!] Error, webrequest failed. Be sure that th ids you gave are correct.')
        exit(1)
    html = http.read()
    soup = BeautifulSoup(html, 'html.parser')
    table = soup.find('table', attrs={'id': 'vulnslisttable'})
    result = [[td.text.encode("utf-8") for td in row.find_all("td")] for row in table.select("tr + tr")]
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

def get_cves(vendor, product, version, filename):
    print('[*] Retrieving cves from version {}'.format(version))
    filename = filename + ".csv"
    write_headers(filename)
    links = get_links(url.format(vid = vendor, pid = product, verid = version))
    cves = []
    print('[*] Writing cves to file {}.csv'.format(filename))
    for link in links:
        cves.extend(get_cves_from_page(link, filename))
    return cves

#------------------------------------------------------------------------------
# Command-line parsing
#------------------------------------------------------------------------------
parser = argparse.ArgumentParser()

parser.add_argument('--vendor',
                    help="Vendor id (required)",
                    action='store',
                    required=True,
                    dest='vendor')
parser.add_argument('--product',
                    help='Product id (required)',
                    action='store',
                    required=True,
                    dest='product')
parser.add_argument('--version',
                    help='Version id (required)',
                    action='store',
                    required=True,
                    dest='version')
parser.add_argument('--csv',
                    help='name of the csv to write the CVEs (required)',
                    action='store',
                    required=True,
                    metavar='<output-filename>',
                    dest='csv')

args = parser.parse_args()

#------------------------------------------------------------------------------
# Retrieving data from website
#------------------------------------------------------------------------------
get_cves(args.vendor, args.product, args.version, args.csv)
