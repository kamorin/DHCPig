#!/bin/sh
##
## gen_changelog.sh
##
## Made by phil
## Login   <phil@reseau-libre.net>
##
## Started on  Tue 23 May 2017 10:01:40 AM CEST phil
## Last update Fri 16 Jun 2017 02:20:10 PM CEST pret
##

set -e

# detect if there is only one upstream tag
num_tags=`git tag|grep -E "^[0-9\.]+"|wc -l`

# current_tag is the one set in debian/changelog
current_tag=`dpkg-parsechangelog -S version|cut -d'-' -f 1|sed -re 's/.dfsg//'`

# current_tag may not be the last upstream tag. previous one should be
# detected depending on the current tag, not the last upstream tag
if [ $num_tags -eq 1 ]; then
  previous_tag=`git rev-list --parents HEAD | egrep "^[a-f0-9]{40}$"`
else
  previous_tag=`git tag|grep -E "^[0-9\.]+"|grep -B 1 "$current_tag"|head -1`
fi

echo "# Release notes for version $current_tag" > changelog
git log --pretty="format:%ci: [%an] %s" --branches=upstream/latest --date=rfc $previous_tag..$current_tag >> changelog
