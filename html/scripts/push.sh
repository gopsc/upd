#!/bin/bash
cd ~
mv mybot/.git .git_github
mv mybot.gitcode/.git mybot/.git
cd mybot
git pull
cd ..
mv mybot/.git mybot.gitcode/.git
mv .git_github mybot/.git
cd mybot
git add .giti*
git commit -m "^-^"
git add *
git commit -m "^-^"
git push
