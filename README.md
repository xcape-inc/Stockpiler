# Stockpiler
##### Created by M4x 5yn74x (Credited to <a href="https://github.com/nomi-sec/">Nomi-sec</a>)
#### Description: GitHub crawler that leverages the <a href="https://github.com/nomi-sec/PoC-in-GitHub">PoC-in-GitHub</a> repository to get the latest updates for the different public CVE PoCs.

### Tools:
#### - `stockpiler-stager.sh` - Stager for Stockpiler. Pulls CVE PoC GitHub URLs from the PoC-in-GitHub and builds appropriate folders on the file system within the project folder.
#### - `stockpiler-stat.sh` - Shows total entries in  Stockpiler, seperating the CVEs and total PoCs available.
#### - `stockpiler-update.sh` - Updates Stockpiler by running `git pull` against the PoC-in-GitHub cloned repo within the project folder, then clones all the newly found CVEs and their respective PoCs.
#### - `stockpiler-search.sh` - Allows the user to search the PoC-in-GitHub repo for CVE IDs or services, such as Citrix, Fortinet, or Ivanti, etc.

### Dependencies:
#### - `ripgrep` - used to quickly search through the PoC-in-GitHub repo for CVE IDs or specific queries, used in the `stockpiler-search.sh` script.
#### - `jq` - used to parse the JSON files for each CVE PoC within the PoC-in-GitHub repo
#### - `wc` - used to get the line count of all captured CVEs and PoCs. Should be installed on Debian by default, but you may want to double check.

### PoC-in-GitHub Dislaimer:
#### As mentioned on the repository, some of these published PoCs are fake, scams, or may contain malware to infect the user of the PoC once downloaded and executed on the user's computer. Please read the source code of every PoC before compiling/executing. Report all malicious repositories collected by their bot to their Issues section of their <a href="https://github.com/nomi-sec/PoC-in-GitHub/issues">repo</a>.

### Stockpiler Disclaimer:
#### The PoCs collected by this tool are for educational and for legitamate Cyber Security testing purposes only. Do not distribute this tool, or host publicly. The creator of this project shall not be held liable for the malicious use of this information or the PoCs collected by this project.

### Disk Space Warning:
#### This is a large collection, currently, as of today, over 312Gs in size and growing. Stockpiler will require at least 1 TB to cover the current collection as well as support more. Migrate to greater disk space as needed.

### Optimal Configuration
#### Given the frequency in which the PoC-in-GitHub is updated, we recommend setting up a cronjob to run every 6 hours. An example is shown below:

<code>0 */6 * * * /opt/Stockpiler/stockpiler-update.sh</code>

### Stockpiler Stats
<pre>
1999 - 4
2000 - 4
2001 - 9
2002 - 16
2003 - 7
2004 - 10
2005 - 6
2006 - 12
2007 - 15
2008 - 19
2009 - 24
2010 - 29
2011 - 24
2012 - 39
2013 - 61
2014 - 99
2015 - 124
2016 - 159
2017 - 287
2018 - 422
2019 - 500
2020 - 677
2021 - 766
2022 - 831
2023 - 1121
2024 - 1316
2025 - 543
</pre>