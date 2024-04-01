import random

def random_IP():
    IPs=[]
    for _ in range(12):
        random_value= random.randint(1,266)
        IPs.append(f'192.168.0.{random_value}')
    return IPs

def check_firewall_rules(ip,action_rule):
    
    if ip in action_rule:
        return action_rule[ip]
    return 'allow'


def main():
    firewall_rules={'192.168.0.15': 'block',
    '192.168.0.25': 'block',
    '192.168.0.45': 'Deny',
    '192.168.0.72': 'block',
    '192.168.0.88': 'Deny',
    '192.168.0.92': 'Deny',
    '192.168.0.98': 'block',
    '192.168.0.122': 'Deny',
    '192.168.0.147': 'block',
    '192.168.0.183': 'Deny',
    '192.168.0.194': 'Deny',
    '192.168.0.202': 'Deny',}
    ip_addresses = random_IP()
    for ip_address in ip_addresses:
   
      action = check_firewall_rules(ip_address,firewall_rules)
      print(f'IP:', ip_address, 'Action:',action)

if __name__ =="__main__":
    main()
