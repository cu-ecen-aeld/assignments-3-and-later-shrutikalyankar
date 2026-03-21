# aesd-assignments
This repo contains public starter source code, scripts, and documentation for Advanced Embedded Software Development (ECEN-5713) and Advanced Embedded Linux Development assignments University of Colorado, Boulder.

## Setting Up Git

Use the instructions at [Setup Git](https://help.github.com/en/articles/set-up-git) to perform initial git setup steps. For AESD you will want to perform these steps inside your Linux host virtual or physical machine, since this is where you will be doing your development work.

## Setting up SSH keys

See instructions in [Setting-up-SSH-Access-To-your-Repo](https://github.com/cu-ecen-aeld/aesd-assignments/wiki/Setting-up-SSH-Access-To-your-Repo) for details.

## Specific Assignment Instructions

Some assignments require further setup to pull in example code or make other changes to your repository before starting.  In this case, see the github classroom assignment start instructions linked from the assignment document for details about how to use this repository.

## Testing

The basis of the automated test implementation for this repository comes from [https://github.com/cu-ecen-aeld/assignment-autotest/](https://github.com/cu-ecen-aeld/assignment-autotest/)

The assignment-autotest directory contains scripts useful for automated testing  Use
```
git submodule update --init --recursive
```
to synchronize after cloning and before starting each assignment, as discussed in the assignment instructions.

As a part of the assignment instructions, you will setup your assignment repo to perform automated testing using github actions.  See [this page](https://github.com/cu-ecen-aeld/aesd-assignments/wiki/Setting-up-Github-Actions) for details.

Note that the unit tests will fail on this repository, since assignments are not yet implemented.  That's your job :) 

Acknowledgements:
1. Used claude to help with this assignment when I had been stuck on an issue for long: shttps://claude.ai/share/6380dfc1-4b78-4183-8462-585c4e723453
2. Used chatgpt to figure out things to fix in code from previous assignment: https://chatgpt.com/share/69add457-e234-8006-96c4-b5a21272416b
