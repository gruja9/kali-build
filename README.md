# Instructions
* Start with [Kali VM](https://www.kali.org/get-kali/#kali-virtual-machines)
* Install Ansible: `python3 -m pip install ansible`
* Install requirements: `ansible-galaxy install -r requirements.yml`
* Make sure we have a sudo token (`sudo whoami`)
* Run the playbook: `ansible-playbook main.yml`