#!/bin/bash
uniq_rules=("IP" "PROTO" "DROP" "PORT" "22")
echo ${#uniq_rules[@]}
echo ${uniq_rules[4]}
