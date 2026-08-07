#!/bin/bash
# SearchCVEDB query tool
# Provide CVEID or general query string.
#
q=$1
# Display matching CVEID for search results
pocresults=$(grep -H -i "$q" CVE-????/CVE-????-*/repos.txt)
cveresults=$(echo "${pocresults[*]}" | cut -d '/' -f2 | sort -u | uniq)
for i in $(echo "${cveresults[*]}");do
        echo -e "\033[1;32mFound related CVE: \033[1;31m$i";echo -en "\033[00m";
        echo -e "\033[1;34mPoC-In-GitHub:";echo -en "\033[00m";
        cat CVE-????/$i/repos.txt
        echo -e "\033[1;35mFound local copy:";echo -en "\033[00m";
        for j in $(ls -d CVE-????/$i/*/*);do
                echo "$j"
        done
done