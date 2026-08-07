#!/bin/bash
echo "Current collection total:"
cvetotal=$(ls CVE-*/ | wc -l)
poctotal=$(cat CVE-*/*/repos.txt | wc -l)
echo "CVEs: $cvetotal"
echo "Proof-of-Concepts: $poctotal"

for cve in $(ls -d CVE-*);do
    cveid=$(find $cve -maxdepth 1 -mindepth 1 -type d | wc -l);
    year=$(echo $cve | cut -d '-' -f2);
    echo "$year - $cveid";
done
echo "Calculating disk usage..."
#diskuse=$(du -sh);
dust -n 23 CVE-*
echo "Complete."
#echo "Total disk usage: $diskuse"