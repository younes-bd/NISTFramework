<h1> Use the NIST Cybersecurity Framework to respond to a security incident</h1>


<h2>Description</h2>
You are a cybersecurity analyst working for a multimedia company that offers web design services, graphic design, and social media marketing solutions to small businesses. Your organization recently experienced a DDoS attack, which compromised the internal network for two hours until it was resolved.
During the attack, your organization’s network services suddenly stopped responding due to an incoming flood of ICMP packets. Normal internal network traffic could not access any network resources. The incident management team responded by blocking incoming ICMP packets, stopping all non-critical network services offline, and restoring critical network services. 
The company’s cybersecurity team then investigated the security event. They found that a malicious actor had sent a flood of ICMP pings into the company’s network through an unconfigured firewall. This vulnerability allowed the malicious attacker to overwhelm the company’s network through a distributed denial of service (DDoS) attack. 
<br />
<br />

To address this security event, the network security team implemented: 
- A new firewall rule to limit the rate of incoming ICMP packets
- Source IP address verification on the firewall to check for spoofed IP addresses on incoming ICMP packets
- Network monitoring software to detect abnormal traffic patterns
- An IDS/IPS system to filter out some ICMP traffic based on suspicious characteristics

As a cybersecurity analyst, you are tasked with using this security event to create a plan to improve your company’s network security, following the National Institute of Standards and Technology (NIST) Cybersecurity Framework (CSF). You will use the CSF to help you navigate through the different steps of analyzing this cybersecurity incident and integrate your analysis into a general security strategy:
- Identify security risks through regular audits of internal networks, systems, devices, and access privileges to identify potential gaps in security. 
- Protect internal assets through the implementation of policies, procedures, training and tools that help mitigate cybersecurity threats. 
- Detect potential security incidents and improve monitoring capabilities to increase the speed and efficiency of detections. 
- Respond to contain, neutralize, and analyze security incidents; implement improvements to the security process. 
- Recover affected systems to normal operation and restore systems data and/or assets that have been affected by an incident.
<br />

<p align="center">
Incident report analysis:  <br/>
Access the incident report analysis template: To access template for this course item, click the following link and select Use Template. <br/>
 
Link to template:<br/>
- Incident report analysis

Link to supporting materials:
- Applying the NIST CSF
- Example of an incident report analysis
<br />
<br />
Summary: <br/>
The company experienced a security event when all network services suddenly stopped responding. The cybersecurity team found the disruption was caused by a distributed denial of services (DDoS) attack through a flood of incoming ICMP packets. The team responded by blocking the attack and stopping all non-critical network services, so that critical network services could be restored.
<br />
<br />
Identify: <br/>
A malicious actor or actors targeted the company with an ICMP flood attack. The entire internal network was affected. All critical network resources needed to be secured and restored to a functioning state.
<br />
<br />
Protect:  <br/>
The cybersecurity team implemented a new firewall rule to limit the rate of incoming ICMP packets and an IDS/IPS system to filter out some ICMP traffic based on suspicious characteristics.
<br />
<br />
Detect: <br/>
The cybersecurity team configured source IP address verification on the firewall to check for spoofed IP addresses on incoming ICMP packets and implemented network monitoring software to detect abnormal traffic patterns. 
<br />
<br />
Respond:  <br/>
For future security events, the cybersecurity team will isolate affected systems to prevent further disruption to the network. They will attempt to restore any critical systems and services that were disrupted by the event. Then, the team will analyze network logs to check for suspicious and abnormal activity. The team will also report all incidents to upper management and appropriate legal authorities, if applicable.
<br />
<br />
Recover: <br/>
To recover from a DDoS attack by ICMP flooding, access to network services need to be restored to a normal functioning state. In the future, external ICMP flood attacks can be blocked at the firewall. Then, all non-critical network services should be stopped to reduce internal network traffic. Next, critical network services should be restored first. Finally, once the flood of ICMP packets have timed out, all non-critical network systems and services can be brought back online.
</p>



Using the NIST Cybersecurity Framework to Respond to a Ransomware Attack

Description:
You are a cybersecurity analyst at a financial institution. The organization recently fell victim to a ransomware attack that encrypted critical customer data and demanded a ransom payment in cryptocurrency. The incident disrupted operations for several days, causing financial losses and reputation damage. Your role is to use the NIST Cybersecurity Framework to guide the response to this incident.

NIST Cybersecurity Framework Steps:

1. Identify:
Incident Type: Ransomware attack.
Affected Systems: Customer data servers, email servers, and internal network.
Impact: Financial losses, reputational damage, and operational disruption.

2. Protect:
Implement Backup and Recovery Procedures: Enhance data backup processes to allow for faster recovery in case of future incidents.
Endpoint Security: Strengthen endpoint security with advanced threat protection software.
User Training: Conduct regular cybersecurity awareness training to reduce the risk of phishing attacks.

4. Detect:
Incident Detection Tools: Implement advanced intrusion detection systems to quickly identify unusual network activity.
Threat Intelligence Sharing: Collaborate with industry peers to receive threat intelligence and detect emerging threats.

4. Respond:
Incident Containment: Isolate affected systems to prevent further encryption and damage.
Law Enforcement Notification: Report the incident to law enforcement and provide requested information.
Communication Plan: Develop a communication plan to notify customers and stakeholders about the incident.
Ransomware Negotiation (if necessary): Engage with law enforcement and cybersecurity experts to assess the feasibility of ransom payment.

6. Recover:
Data Restoration: Restore encrypted data from backups and ensure its integrity.
System Hardening: Strengthen security measures to prevent similar incidents in the future.
Lessons Learned: Conduct a post-incident review to identify weaknesses and improve incident response procedures.
Ongoing Monitoring: Implement continuous monitoring and threat detection to detect and respond to future incidents promptly.

Incident Report Analysis:
Summary: The organization experienced a ransomware attack that encrypted critical customer data, causing financial losses and operational disruption.
Identify: The incident was identified as a ransomware attack, affecting customer data servers, email servers, and the internal network.
Protect: Protective measures included enhancing data backup procedures, improving endpoint security, and conducting user training.
Detect: Advanced intrusion detection systems and threat intelligence sharing were implemented to detect and respond to threats.
Respond: Incident response involved isolating affected systems, notifying law enforcement, and developing a communication plan. Ransomware negotiation was considered.
Recover: Data restoration, system hardening, lessons learned, and ongoing monitoring were key steps in the recovery process.




Using the NIST Cybersecurity Framework to Respond to a Phishing Attack

Description:
You are a cybersecurity analyst at a technology company. The organization recently experienced a phishing attack that resulted in multiple employees unknowingly disclosing their login credentials. This incident raised concerns about potential data breaches and unauthorized access. Your role is to use the NIST Cybersecurity Framework to guide the response to this incident.

NIST Cybersecurity Framework Steps:

1. Identify:
Incident Type: Phishing attack.
Affected Systems: Employee email accounts and potentially sensitive data.
Impact: Potential data exposure and unauthorized access.

3. Protect:
Employee Training: Conduct immediate phishing awareness training for all employees.
Email Filtering: Enhance email filtering to detect and block phishing emails.
Multi-Factor Authentication (MFA): Enforce MFA for accessing sensitive systems and data.

3. Detect:
Threat Hunting: Initiate threat hunting activities to identify potential signs of data compromise.
Incident Response Team Activation: Activate the incident response team to investigate the extent of the breach.
4. Respond:

Account Lockout: Lock out affected email accounts to prevent unauthorized access.
Password Reset: Promptly reset passwords for impacted accounts.
Data Inventory: Conduct an inventory of potentially exposed data.
Legal Obligations: Assess and comply with legal obligations regarding data breach notification.
5. Recover:

Data Remediation: Remove exposed data and conduct a forensic analysis.
Communication Plan: Develop a communication plan for notifying affected individuals.
Incident Review: Conduct a post-incident review to identify vulnerabilities and improve incident response.
Incident Report Analysis:

Summary: The organization experienced a phishing attack that resulted in compromised employee email accounts, potentially exposing sensitive data.
Identify: The incident was identified as a phishing attack impacting email accounts and data.
Protect: Protective measures included employee training, email filtering, and enforcing MFA.
Detect: Threat hunting and incident response team activation were key steps in detection.
Respond: Immediate actions included locking out accounts, resetting passwords, and conducting a data inventory.
Recover: Data remediation, communication planning, and incident review were crucial for recovery.



Using the NIST Cybersecurity Framework to Respond to a Data Leak Incident

Description:
You are a cybersecurity analyst at a healthcare organization. An internal audit revealed an unauthorized data leak where a former employee accessed and copied sensitive patient records. Your role is to use the NIST Cybersecurity Framework to guide the response to this data leak incident.

NIST Cybersecurity Framework Steps:

1. Identify:
Incident Type: Unauthorized data leak.
Affected Systems: Patient record database.
Impact: Potential patient data exposure and privacy violation.

3. Protect:
Access Controls: Review and enhance access controls to prevent unauthorized data access.
Employee Training: Reinforce data handling policies and provide training on data security.


3. Detect:
Data Leak Detection Tools: Implement data leak detection tools to monitor data access and movement.
Incident Response Team Activation: Activate the incident response team to investigate the incident.

5. Respond:
Account Suspension: Suspend the former employee's account and access privileges.
Data Forensics: Conduct forensic analysis to determine the extent of the data leak.
Legal Notifications: Notify legal authorities and affected patients as required by data breach laws.

5. Recover:
Data Restoration: Restore data affected by the breach from secure backups.
Access Control Improvements: Implement improved access controls and regular access reviews.
Incident Review: Conduct a post-incident review to identify weaknesses and enhance data security.

Incident Report Analysis:
Summary: The organization experienced an unauthorized data leak incident involving sensitive patient records.
Identify: The incident was identified as an unauthorized data leak from the patient record database.
Protect: Measures included access control enhancements and employee training.
Detect: Data leak detection tools and incident response team activation were essential for detection.
Respond: Immediate actions involved suspending accounts, conducting data forensics, and legal notifications.
Recover: Data restoration, access control improvements, and incident review were critical for recovery.
These examples demonstrate how the NIST Cybersecurity Framework can be applied to respond to various security incidents, such as phishing attacks and data leaks. You can adapt these examples to your portfolio as needed. If you require more examples or have specific scenarios in mind, please let me know!



Using the NIST Cybersecurity Framework to Respond to a Malware Infection

Description:
You are a cybersecurity analyst at a financial institution. The organization's network has been infected with malware that has the potential to steal sensitive customer data. Your role is to use the NIST Cybersecurity Framework to guide the response to this malware infection incident.

NIST Cybersecurity Framework Steps:

1. Identify:
Incident Type: Malware infection.
Affected Systems: Multiple endpoints across the organization.
Impact: Potential data theft, financial loss, and network disruption.

3. Protect:
Endpoint Security: Review and update endpoint security solutions.
Employee Training: Conduct training on identifying and avoiding malware.

3. Detect:
Endpoint Monitoring: Enhance real-time monitoring of endpoints for suspicious activity.
Incident Response Team Activation: Activate the incident response team to investigate the malware infection.

5. Respond:
Isolation: Isolate infected endpoints from the network to prevent further spread.
Malware Removal: Deploy malware removal tools to affected systems.
Data Assessment: Evaluate the extent of data exposure and theft.
Legal Notifications: Comply with legal obligations regarding data breach notifications.

5. Recover:
System Restoration: Restore affected systems from clean backups.
Security Improvements: Implement improved security measures to prevent future malware infections.
Post-Incident Review: Conduct a post-incident review to identify vulnerabilities and enhance security practices.

Incident Report Analysis:
Summary: The organization experienced a malware infection incident with the potential for data theft and network disruption.
Identify: The incident was identified as a malware infection affecting multiple endpoints.
Protect: Protective measures included endpoint security updates and employee training.
Detect: Enhanced endpoint monitoring and incident response team activation aided in detection.
Respond: Immediate actions involved isolation, malware removal, data assessment, and legal notifications.
Recover: System restoration, security improvements, and post-incident review were crucial for recovery.


Using the NIST Cybersecurity Framework to Respond to a Denial of Service (DoS) Attack

Description:
You are a cybersecurity analyst at an e-commerce company. The organization's website recently experienced a Distributed Denial of Service (DDoS) attack, causing the website to become unavailable for several hours. Your role is to use the NIST Cybersecurity Framework to guide the response to this DDoS attack incident.

NIST Cybersecurity Framework Steps:
1. Identify:
Incident Type: DDoS attack.
Affected Systems: E-commerce website and associated services.
Impact: Website unavailability, potential financial loss, and brand reputation damage.

3. Protect:
DDoS Mitigation: Implement DDoS mitigation solutions to protect against future attacks.
Redundancy: Establish redundant hosting to maintain website availability during attacks.

3. Detect:
Network Traffic Analysis: Enhance network traffic analysis to detect abnormal patterns.
Incident Response Team Activation: Activate the incident response team to investigate the DDoS attack.

5. Respond:
Traffic Filtering: Implement traffic filtering to block malicious traffic.
Communication: Notify stakeholders about the ongoing attack and expected downtime.
Legal Notifications: Comply with legal obligations regarding service interruptions.

5. Recover:
Website Restoration: Restore the website to normal operation once the attack subsides.
Long-Term Defense: Review and enhance long-term DDoS defense strategies.
Post-Incident Review: Conduct a post-incident review to identify vulnerabilities and improve resilience.

Incident Report Analysis:
Summary: The organization experienced a DDoS attack that resulted in the unavailability of the e-commerce website.
Identify: The incident was identified as a DDoS attack affecting the website and services.
Protect: Protective measures included DDoS mitigation and redundancy.
Detect: Network traffic analysis and incident response team activation aided in detection.
Respond: Immediate actions involved traffic filtering, communication, and legal notifications.
Recover: Website restoration, long-term defense planning, and post-incident review were essential for recovery.

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
