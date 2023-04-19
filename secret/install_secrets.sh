#!/bin/bash

# example of using arguments to a script
mkdir -p resource
mkdir -p /opt/confidential-containers/kbs/repository/quark_mongo

pushd mogo_secret

for filename in *; do

# echo "$filename"
# read -rd '' content < $filename

# jq -r '@base64' $filename > ../resource/$filename
cat $filename | base64 | tr -d '\n' > ../resource/$filename

# cp --parent ../quark_secret/$filename /opt/confidential-containers/kbs/repository/quark_mongo
done


popd

cp -R resource  /opt/confidential-containers/kbs/repository/quark_mongo
