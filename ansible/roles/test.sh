ansible-playbook -i 192.168.1.20, -e "ansible_user=hpistor ansible_ssh_pass=sabals12 ansible_sudo_pass=sabals12 ansible_ssh_common_args='-o StrictHostKeyChecking=no'" playbook.yml
