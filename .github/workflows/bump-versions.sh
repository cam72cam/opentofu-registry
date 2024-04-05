#!/bin/bash

if [ -z "${PREFIX}" ]; then
	echo "Expecting \$PREFIX to be set"
	exit 1
fi
if [ -z "${GITHUB_REF}" ]; then
	echo "Expecting \$GITHUB_REF to be set"
	exit 1
fi
if [ -z "${GITHUB_RUN_NUMBER}" ]; then
	echo "Expecting \$GITHUB_RUN_NUMBER to be set"
	exit 1
fi
if [ -z "${ENVIRONMENT}" ]; then
	echo "Expecting \$ENVIRONMENT to be set"
	exit 1
fi

cd ./src
go run ./cmd/bump-versions -module-namespace "${PREFIX}" -provider-namespace "${PREFIX}"
cd ../

BRANCH="${GITHUB_REF}-bump-versions-${GITHUB_RUN_NUMBER}"
if [ "${ENVIRONMENT}" = "Production" ]; then
	export BRANCH="${GITHUB_REF}"
fi

# Try to get to the latest HEAD
git fetch origin
git checkout -b $BRANCH
git reset --hard origin/$BRANCH

# Commit changes
git add ./modules ./providers
git commit --author "OpenTofu Core Development Team <core@opentofu.org>" -m "Automated bump of versions for providers and modules"

# Racing with other jobs, try a few times to push changes
for i in {0..30}; do
	git fetch origin
	git rebase origin/$BRANCH
	git push -u origin $BRANCH
done

echo "Providers and modules changes were pushed to branch: ${BRANCH}"
