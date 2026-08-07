#!/bin/bash
# CVEDB Stager
# Parses the CVE ID from the PoC-in-GitHub repository to create the directory structure for the CVEDB project.
echo "CVEDB Stager"
if [ ! -d "PoC-in-GitHub" ];then
        echo "PoC-in-GitHub repo not detected on this system."
        echo "Cloning https://github.com/nomi-sec/PoC-in-GitHub now..."
        git clone https://github.com/nomi-sec/PoC-in-GitHub
fi
echo "Creating directory structure for the database..."
pigrepo="PoC-in-GitHub";
for i in $(ls $pigrepo);do
        if [ "$i" == "README.md" ];then
                break;
        else
                #echo "CVE-$i";
                mkdir CVE-$i
                for j in $(ls $pigrepo/$i);do
                        cveid=$(echo $j|cut -d "." -f1);
                        echo "CVE-$i/$cveid";
                        mkdir CVE-$i/$cveid
                        for k in $(cat $pigrepo/$i/$j | jq | grep "full_name"|cut -d ":" -f 2);do
                                fn=$(echo "$k"| tr '",' ' ' | cut -d ' ' -f2);
                                gitrepo="https://github.com/$fn";
                                #echo $gitrepo;
                                echo $gitrepo >> CVE-$i/$cveid/repos.txt
                        done;
                done;
        fi;
done
echo "Directory structure created."
echo "Proceeding to clone all CVE repositories..."
for i in $(ls | grep "CVE");do
        #echo $i;
        for j in $(ls $i);do
                #echo $j;
                for k in $(ls $i/$j);do
                        #echo $k;
                        n=1;
                        for l in $(cat $i/$j/$k);do
                                reponame=$(echo "$l" |cut -d '/' -f 5)
                                echo "Cloning Github repository: $l to $i/$j/$n/$reponame";
                                git clone $l $i/$j/$n/$reponame
                                sleep 5 # Don't make GitHub angry.
                                n=$((n+1));
                        done;
                done;
        done;
done
echo "CVEDB installed. Use the searchcvedb.sh tool to query the data"