#!/bin/bash

# ZSH_History
rm ~/.zsh_history

# NXC
rm ~/.nxc/logs/* ~/.nxc/workspaces/default/* -R

# Responder
sudo rm /usr/share/responder/Responder.db

# SCCMHunter
rm ~/.sccmhunter/logs/* -R

# Bloodhound CE
docker volume rm bloodhoundce_neo4j-data

# Lsassy
rm ~/.config/lsassy -R
