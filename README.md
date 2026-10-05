# Active-Directory-Lab


# Objective

The goal of this project was to construct a simulated, secure network environment and observe firsthand the dynamics of cyber threats and defenses. By establishing an Active Directory structure and integrating Splunk for event monitoring, the project aimed to offer a tangible understanding of how various cybersecurity tools interact and how potential intrusions can be detected and analyzed within a controlled setting. The overarching objective was to craft an insightful narrative that could be shared to help others learn about the nuances of network security through practical engagement.

# Skills Learned

- Network configuration and management.
- Active Directory setup and user management.
- Brute force attack methods and their signatures.
- Event logging and monitoring.
- Usage of the MITRE ATT&CK Framework for understanding threat models.

# Tools Used

- VirtualBox for virtualization.
- Kali Linux for penetration testing.
- Windows Server 2022 and Windows 10 for setting up a target environment.
- Splunk for data aggregation and analysis.
- Hydra and Atomic Red Team for simulating attacks.

# Steps Taken
## Design and Visualization:
- Developed a comprehensive logical diagram to establish a clear vision of the data flow and overall structure of the project.

## Virtual Environment Setup:
- Deployed all required virtual machines to create a diverse and interactive network.
- Executed network configuration to ensure all systems operate on the same NAT-Network, facilitating communication and internet access.

## IP Configuration and Monitoring Infrastructure:
- Assigned static IP addresses to each virtual machine, adhering to the initial project design.
- Installed and configured Splunk on Ubuntu, along with the Splunk Universal Forwarder and Sysmon on Windows platforms for event monitoring.

## Active Directory Installation and Configuration:
- Installed Active Directory on Windows Server and promoted it to a domain controller to manage network resources securely and efficiently.

## Organizational Structure and Access Management:
- Created organizational units representing different departments and provisioned user accounts, setting the stage for role-based access control.

## Network Integration and Domain Connectivity:
- Seamlessly integrated the target Windows machine into the domain, consolidating the network and enabling centralized management.

## Attack Simulation, Detection, and Learning:
- Executed a brute force attack using Hydra to test network defenses.
- Employed Splunk for the detection and analysis of attack patterns, facilitating a practical understanding of event logs and security breaches.
- Utilized Atomic Red Team for further attack simulations, enhancing detection capabilities.
- Expanded knowledge of key Windows event codes and the MITRE ATT&CK Framework, applying this to the threat simulation and detection processes.


# Conclusion:
The key takeaways from this project reinforce the notion that security is not a static field; it requires constant learning and adaptation. Tools and strategies must be continually evaluated and tested against emerging threats. The use of Hydra illustrated the critical need to select the right tools for specific scenarios, which could mean the difference between a breached and a secure system.

Moreover, this project showcased that practical, hands-on projects serve as excellent learning conduits, significantly enhancing one's understanding and skills in cybersecurity.
