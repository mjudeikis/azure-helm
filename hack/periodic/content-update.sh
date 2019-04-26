make content

CONTENT_BRANCH="update-content"
PR_TITLE="Automated Content Update"
PR_AUTHOR="openshift-azure-bot"
PR_EMAIL="aos-azure@redhat.com"

if [[ -n "$(git status --porcelain)" ]]; then
	echo "content update produced template and image-stream changes that were not already present"

	. hack/tests/ci-operator-prepare.sh

    git remote rm origin2
    git remote add origin2 https://${PR_AUTHOR}:${GITHUB_TOKEN}@github.com/mjudeikis/openshift-azure.git

    # check if PR exist
    git fetch origin2
    git rev-parse --verify origin2/${CONTENT_BRANCH}
    # create new branch or reuse old
    if [ $? == 1 ]; then
        echo "branch $CONTENT_BRANCH does not exist"
        git checkout upstream/master
        git checkout -b $CONTENT_BRANCH
    else 
        git checkout origin2/$CONTENT_BRANCH
    fi

        git add *
        git commit -m "${PR_TITLE}"

else
	echo "Dependencies have no material difference than what is committed."
fi

