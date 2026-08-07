#!/bin/bash
# CVEDB Update script.
# Run git pull inside the PoC-in-GitHub cloned repo for the latest updates
# Disable interactive credential prompts
export GIT_TERMINAL_PROMPT=0
pigrepo="PoC-in-GitHub"
declare -a created_repos
declare -a updated_repos
echo "Checking for updates from $pigrepo..."
cd $pigrepo;
if $(git pull | grep -q "Already");then
        echo "Already up to date.";
else
        echo "Cloning new updates to CVEDB...";
fi
cd ..
# Loop through the repo to gather all updated data and append to the database in CVEDB
for i in $(ls $pigrepo | grep -v README.md);do
    #echo $i
    for j in $(ls $pigrepo/$i);do
        cveid=$(echo $j | cut -d '.' -f1);
        for k in $(cat $pigrepo/$i/$j | jq | grep "full_name"|cut -d ":" -f 2);do
            fn=$(echo "$k"| tr '",' ' ' | cut -d ' ' -f2);
            gitrepo="https://github.com/$fn";
            #echo "Checking: CVE-$i/$cveid/repos.txt..."
            if [[ ! -d "CVE-$i/$cveid" ]];then
                echo "Collection does not exist for CVE-$i/$cveid"
                echo "Creating now..."
                mkdir CVE-$i/$cveid
                mkdir CVE-$i/$cveid/1
                echo "Appending to CVE-$i/$cveid/repos.txt"
                echo "$gitrepo" >> CVE-$i/$cveid/repos.txt
                reponame=$(echo $gitrepo | cut -d '/' -f 5)
                echo "Cloning new GitHub repo: $gitrepo to CVE-$i/$cveid/1/$reponame"
                git clone $gitrepo CVE-$i/$cveid/1/$reponame
                sleep 5 # Don't make GitHub angry
                created_repos+="CVE-$i/$cveid"
                created_repos+=" "
            elif grep -q "$gitrepo" CVE-$i/$cveid/repos.txt;then
                break
            else
                echo "Repo: $gitrepo - not found in current collection."
                echo "Downloading now..."
                d=$(ls CVE-$i/$cveid | grep -v "repos.txt" | wc -l)
                #echo "Current PoC entry: $d"
                n=$((d + 1))
                #echo "Creating new folder: $n"
                echo "Appending to CVE-$i/$cveid/repos.txt"
                echo $gitrepo >> CVE-$i/$cveid/repos.txt
                reponame=$(echo $gitrepo | cut -d '/' -f 5)
                echo "Cloning GitHub repo: $gitrepo to CVE-$i/$cveid/$n/$reponame"
                git clone $gitrepo CVE-$i/$cveid/$n/$reponame
                sleep 5 # Don't make GitHub angry
                updated_repos+="CVE-$i/$cveid"
                updated_repos+=" "
            fi
        done
    done
done

echo "CVEDB update has finished"
if [ ${#created_repos[@]} -eq 0 ];then
    echo "No new entries."
else
    echo "New entries:"
    for x in $( echo "${created_repos[*]}" | sort -u | uniq );do
        echo $x
    done
fi
if [ ${#updated_repos[@]} -eq 0 ];then
    echo "No updated entries."
else
    echo "Updated entries:"
    for y in $( echo "${updated_repos[*]}" | sort -u | uniq );do
        echo $y
    done
fi

echo "Current collection total:"
cvetotal=$(ls CVE-*/ | wc -l)
poctotal=$(cat CVE-*/*/repos.txt | wc -l)
echo "CVEs: $cvetotal"
echo "Proof-of-Concepts: $poctotal"