import dns.resolver
import re


def checkDMARC(domain):
    # Remove any leading "https://", "www.", or "http://" from the domain
    domain = re.sub(r'^https?://(?:www\.)?', '', domain)
    
    # Query the DMARC record of the domain
    try:
        dmarc_record = dns.resolver.resolve('_dmarc.' + domain, 'TXT')
    except dns.resolver.NXDOMAIN:
        return("Checks the DMARC record of a domain: " + f"{domain} is vulnerable (No DMARC record found)")

    # Parse the DMARC record and determine the policy
    dmarc_policy = None
    for txt_string in dmarc_record:
        match = re.search(r'p=([a-z]+)', str(txt_string))
        if match:
            dmarc_policy = match.group(1)
            break
    print("HERE DMARC")
    # Print a message indicating whether the domain is vulnerable to email spoofing
    if dmarc_policy == 'reject':
        return("Checks the DMARC record of a domain: " + f"{domain} is NOT vulnerable")
    elif dmarc_policy == 'quarantine':
        return("Checks the DMARC record of a domain: " + f"{domain} can be vulnerable (email will be sent to spam)")
    elif dmarc_policy == 'none':
        return("Checks the DMARC record of a domain: " + f"{domain} is vulnerable")
    else:
        return("Checks the DMARC record of a domain: " + f"{domain} is vulnerable (No DMARC policy found)")
