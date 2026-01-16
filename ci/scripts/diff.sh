#!/bin/bash

# Get the git status in porcelain format
status=$(git status --porcelain)

# Check if the status output is empty
if [ -n "$status" ]; then
  # If not empty, run git diff --patch and send output to stdout
  echo "$status"
  git diff --patch
fi