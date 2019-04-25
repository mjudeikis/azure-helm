#!/bin/bash -e

make content


if [[ -n "$(git status --porcelain)" ]]; then
	echo "content update produced template and image-stream changes that were not already present"
	
	. hack/tests/ci-operator-prepare.sh
	go run hack/giter/giter.go -sourcerepo mjudeikis/openshift-azure -targetrepo mjudeikis/openshift-azure

fi

echo "Dependencies have no material difference than what is committed."
