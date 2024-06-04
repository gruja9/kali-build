#!/bin/bash

# ZSH_History
rm ~/.zsh_history

# NXC
rm ~/.nxc/logs/* ~/.nxc/workspaces/default/* -R

# Responder
sudo rm /usr/share/responder/Responder.db

# SCCMHunter
rm ~/.sccmhunter/logs/* -R

# Lsassy
rm ~/.config/lsassy -R
