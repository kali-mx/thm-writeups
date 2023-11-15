# thm-writeups
Writeups created in Markdown using VS Code linked with Github



# Chapter: Extracting and Cracking NTLM Hashes with Python

## Introduction

In the realm of penetration testing, understanding and exploiting vulnerabilities is paramount. One key aspect of this process is the extraction and cracking of NTLM hashes, a critical step in compromising user credentials. This chapter focuses on a Python script designed for this purpose, employing Impacket and Hashcat in the Kali Linux environment. Join us on a journey through the intricacies of NTLM hash extraction and the subsequent cracking process.

### Objective

The primary goal of this chapter is to equip penetration testers with the knowledge and skills needed to extract and crack NTLM hashes. We delve into the script's functionality, unraveling its inner workings and demonstrating how each function contributes to the larger penetration testing workflow.

## Understanding the Script

### Overview of the Script

At the core of our exploration is a Python script that seamlessly integrates Impacket and Hashcat for efficient NTLM hash extraction and cracking. Before we dive into the script's details, let's establish a broad understanding of its purpose and significance in penetration testing.

#### Purpose

The script is designed to automate the extraction of NTLM hashes from a Windows domain controller using Impacket, followed by the cracking of those hashes using Hashcat. This process enables penetration testers to identify weak passwords and potential vulnerabilities within a target system.

#### Components

Two crucial components drive the script's functionality: Impacket and Hashcat. Impacket, a collection of Python classes, facilitates interaction with Windows protocols, while Hashcat specializes in password cracking. Together, they form a formidable toolkit for penetration testers.

### Script Execution

Before we delve into the intricacies of the script's functions, let's explore how the script is executed. Understanding the command-line parameters is crucial for tailoring the script to specific penetration testing scenarios.

#### Command-Line Arguments

The script accepts several command-line arguments to customize its behavior:
- **-d, --domain:** Specifies the domain name.
- **-u, --user:** Specifies the username (optional).
- **-p, --password:** Specifies the password (optional).
- **-ip, --ipaddress:** Specifies the IP address (optional).
- **-w, --wordlist:** Specifies the wordlist for Hashcat.
- **-r, --rules:** Specifies Hashcat rules (optional).
- **-O, --optimized:** Enables optimized mode in Hashcat.


Script Execution (Continued)
Running the Script

Now, let's explore how to execute the script with various command-line parameters:

bash

./script_name.py -d example.com -u username -p password -ip 192.168.1.1 -w wordlist.txt -r rules -O

In this example:

    -d, --domain: Specifies the domain name as "example.com."
    -u, --user: Specifies the username as "username."
    -p, --password: Specifies the password as "password."
    -ip, --ipaddress: Specifies the IP address as "192.168.1.1."
    -w, --wordlist: Specifies the wordlist for Hashcat as "wordlist.txt."
    -r, --rules: Specifies Hashcat rules as "rules."
    -O, --optimized: Enables optimized mode in Hashcat.

This flexibility allows penetration testers to adapt the script to diverse testing scenarios.

Extracting NTLM Hashes

Our journey into NTLM hash extraction begins with the run_secretsdump function, a critical part of the script that interfaces with Impacket to obtain NTLM hashes from a Windows domain controller.
run_secretsdump Function

The run_secretsdump function is responsible for crafting and executing the Impacket command to extract NTLM hashes. Let's break down its key components:

python

def run_secretsdump(args):
    if args.user:
        cmd = f"impacket-secretsdump {args.domain}/{args.user}:'{args.password}'@{args.ipaddress} -just-dc-ntlm"
    else:
        cmd = f"impacket-secretsdump -k -no-pass {args.domain}"

    print("Secretsdump is working...\n")

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    lines = result.stdout.split('\n')

    start = False
    relevant_lines = []
    nt_hashes = []

    for line in lines:
        # ...
        # (Code for processing lines and extracting NTLM hashes)
        # ...

    with open('ntds-hashes.txt', 'w') as file:
        file.write("\n".join(relevant_lines))
    
    with open('nt-hashes.txt', 'w') as file:
        file.write('\n'.join(nt_hashes))

In the above code:

    The Impacket command is dynamically generated based on the provided command-line arguments.
    The script executes the command and captures the output.
    The output is processed to identify relevant lines containing NTLM hashes, which are then saved to files for further use.

This function sets the stage for the subsequent Hashcat cracking process.
Cracking NTLM Hashes (Continued)
run_hashcat Function

With NTLM hashes extracted, the run_hashcat function takes center stage, orchestrating the Hashcat engine for the cracking endeavor.

python

def run_hashcat(args):
    hash_cat = f"hashcat -m 1000 nt-hashes.txt {args.wordlist}"
    if args.rules:
        hash_cat += " -O"
    print(f"Executing: {hash_cat}")

    result = subprocess.run(hash_cat, shell=True, capture_output=True, text=True)
    
    recovered_match = re.search(r'Recovered\.\.\.\.\.\.\.\.: (\d+)/(\d+)', result.stdout)
    
    if recovered_match:
        # ...
        # (Code for processing Hashcat results)
        # ...

        if recovered_hashes > 0:
            run_hashcat_show(args)

Breaking down the run_hashcat function:

    The Hashcat command is dynamically constructed based on the provided command-line arguments, such as the hash mode, hash file, wordlist, and optional rules.
    The script executes the Hashcat command and captures the output.
    The output is processed to determine the number of recovered hashes, providing insights into the success of the cracking attempt.
    If hashes are successfully cracked, the run_hashcat_show function is called to display and save the results.

run_hashcat_show Function

The run_hashcat_show function completes the cracking phase, showcasing the cracked usernames and passwords.

python

def run_hashcat_show(args):
    hashcat_show_cmd = f"hashcat -m 1000 nt-hashes.txt --show"
    show_result = subprocess.run(hashcat_show_cmd, shell=True, capture_output=True, text=True)
    
    with open("ntds-hashes.txt", "r") as file:
        original_data = file.readlines()

    # ...
    # (Code for correlating cracked hashes with original usernames)
    # ...

    with open(f"{args.domain}-cracked-users.txt", "w") as file:
        # ...
        # (Code for writing cracked usernames and passwords to a file)
        # ...

    print(f"\n\nResults are saved to {args.domain}-cracked-users.txt")

In this function:

    Hashcat is invoked to show the cracked hashes.
    The script correlates the cracked hashes with the original usernames extracted during the NTLM hash extraction phase.
    The results are saved to a file, providing a concise record of the compromised credentials.

Script Execution in Action (Continued)
Running the Script (Continued)

Let's now explore the practical execution of the script in a penetration testing scenario. We'll walk through real-world examples, showcasing the extraction and cracking of NTLM hashes.

Certainly! Let's continue with the expansion of the last section.

---

### Running the Script (Continued)

#### Practical Execution

To illustrate the script's real-world applicability, let's walk through a practical scenario. Consider a penetration testing engagement where you have obtained the necessary information to run the script:

```bash
./script_name.py -d example.com -u administrator -p AdminPass123 -ip 192.168.1.1 -w rockyou.txt -r best64.rule -O
```

In this example:
- **-d, --domain:** Specifies the target domain as "example.com."
- **-u, --user:** Specifies the username as "administrator."
- **-p, --password:** Specifies the password as "AdminPass123."
- **-ip, --ipaddress:** Specifies the IP address of the domain controller as "192.168.1.1."
- **-w, --wordlist:** Utilizes the "rockyou.txt" wordlist for Hashcat.
- **-r, --rules:** Applies Hashcat rules from the "best64.rule" file.
- **-O, --optimized:** Enables Hashcat's optimized mode.

#### Observing the Script in Action

As the script executes, it provides informative output about its progress. Let's break down the steps of the practical execution:

1. **NTLM Hash Extraction:**
   - The `run_secretsdump` function initiates Impacket to interact with the target domain controller.
   - NTLM hashes are extracted from the domain controller's NTDS.DIT database.
   - Extracted hashes are saved in `ntds-hashes.txt` and `nt-hashes.txt` for further analysis.

2. **Hash Cracking with Hashcat:**
   - The `run_hashcat` function constructs a Hashcat command based on specified parameters.
   - Hashcat commences the cracking process using the provided wordlist and rules.
   - The script monitors Hashcat's progress and displays the number of recovered hashes.

3. **Displaying Cracked Usernames and Passwords:**
   - If Hashcat successfully cracks hashes, the `run_hashcat_show` function is invoked.
   - Cracked hashes are correlated with the original usernames.
   - Results are saved to a file named `<domain>-cracked-users.txt`.

4. **Summary:**
   - The penetration tester gains insights into weak passwords within the target domain.
   - Cracked usernames and passwords are stored for further analysis and reporting.

#### Customizing for Specific Scenarios

The strength of the script lies in its adaptability to diverse scenarios. By adjusting command-line parameters such as the wordlist, rules, and optimization mode, penetration testers can tailor the script to the unique characteristics of their target environments.

## Conclusion

In this chapter, we've explored a Python script designed for the extraction and cracking of NTLM hashes in a penetration testing context. Leveraging Impacket and Hashcat, the script streamlines the process of identifying weak passwords within a target domain. Penetration testers armed with this knowledge gain a powerful tool for assessing and fortifying system security.

As we conclude this chapter, reflect on the importance of NTLM hash extraction and cracking in penetration testing. The hands-on experience gained through the script empowers security professionals to proactively identify and address potential vulnerabilities, contributing to a more robust and resilient security posture.






