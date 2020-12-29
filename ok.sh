#!/bin/bash
a="80,22,8080"
IFS=','
read -a arr <<< "$a"
echo ${arr[@]}
i=2
arr[$i]="23"
echo ${arr[@]}
