@echo off
REM Quick push script - stages all changes, amends commit, and force pushes

echo Staging all changes...
git add .

echo Amending commit...
git commit --amend --no-edit

echo Force pushing to master...
git push origin master --force

echo Done!
pause
