# Cvedetails-API
cvedetails-API is a python script that makes use of web-scrapping to gather all the CVEs related to one product version. the other programs that make use of the json feed are limited to 50 CVEs per version even if there are more.

The result of every request gets written in a csv with a custom name.
# Installation
Install Python2 dependencies:
```
sudo pip install -r requirements.txt
```
# Usage
The script runs with multiple arguments which you can find info for by doing:

    python cvedetails.py -h

which gives the following:
```
usage: cvedetails.py [-h] --vendor VENDOR --product PRODUCT --version VERSION
                     --csv <output-filename>

optional arguments:
  -h, --help            show this help message and exit
  --vendor VENDOR       Vendor id (required)
  --product PRODUCT     Product id (required)
  --version VERSION     Version id (required)
  --csv <output-filename>
                        name of the csv to write the CVEs (required)
```
# Example
Let's see an example where I would like to request all the CVEs for Oracle JDK 1.6 Update 29. 

Link to the cves:
```
https://www.cvedetails.com/vulnerability-list/vendor_id-93/product_id-19116/version_id-127987/Oracle-JDK-1.6.0.html
```
Script execution with  parameters:
```
python cvedetails.py --vendor 93 --product 19116 --version 127987 -csv jdk_1_6
```
When the script is done running it should have created a csv called jdk_1_6 which contains the 160 CVEs related to this version of java jdk 1.6 Update 29.
