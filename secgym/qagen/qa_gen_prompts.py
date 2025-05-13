TWEAKED_QAGEN_PROMPT_ORIGIN = """

Your goal is to ask a security question to test a junior security analyst's ability to understand a security incident and their reasoning capabilities.
You will be given a security incident composed of a group of related alerts connected by data elements or entities that are shared between the alerts such as User accounts, Hosts, Mailboxes, IP addresses, Files, Cloud applications, Processes, URLs etc. Alerts are signals that result from various threat detection activities. These signals indicate the occurrence of malicious or suspicious events in your environment.

Specifically to generate a question, you will be given an alert-entity path from the given security incident. This will include a start alert and end alert, and corresponding entities involved in the start and end alert. The two alerts are connected by a alert-entity path. Some of the entities on the alert-entity path are ommitted (replaced by ???) in order to test the junior analyst's ability to find these connections on their own. The start and end alert might be the same.
You will use the start alert along with the overall incident details as the context, and ask a question about the entities part of the end alert.

The JSON must have the following fields:
- "question": the question about the end alert. The question should be carefully crafted so that:
    1. The question should be natural and relevant to the context, and it should be clear and have a deterministic answer.
    2. But it should not leak the answer. If the start and end alert are the same, you should be more careful since the given entities may have overlapping information.
    3. The question should be specific of the answer you are looking for, and the answer should match the question.
- "answer": the answer to the question. You may be given one or more entities from the end alert, select the most meaningful entity and make sure it is not leaked in the context or question.
- "context": the context from the start alert and overall incident. You should combine the alert and the entities given in a consistent sentence. You can simplify the context a bit if it is too long. Make sure the answer is not leaked in the context. If the start alert or the related entities contains the answer, you should remove it from the context.

Examples:
##############
Security Incident: Multi-stage incident involving Initial access & Collection on multiple endpoints reported by multiple sources, Description: nan, Severity: High, Time of incident: from 2024-08-01 12:26:22+00:00 to 2024-08-01 12:37:30.277218+00:00, Additional Details: {"alertsCount":9,"bookmarksCount":0,"commentsCount":1,"alertProductNames":["Microsoft Defender Advanced Threat Protection","Azure Security Center","Microsoft 365 Defender","Office 365 Advanced Threat Protection","Azure Sentinel"],"tactics":["DefenseEvasion"],"techniques":["T1003","T1018","T1069","T1087","T1482","T1566","T1496"]"}

Start Alert:
Time: 8/14/2024, 10:34:41.578 PM
Name: Ntdsutil collecting Active Directory information
Description: Attackers might be using Ntdsutil to gather information for persistence or to move laterally in a network or organization. Ntdsutil is a command line tool that provides management facilities for Active Directory Domain Services (AD DS) and Active Directory Lightweight Directory Services (AD LDS). It was launched to maintain the database of AD DS.
Entities from this alert:
Type: process, Field: ExtractedFileName, Value: `powershell.exe`
Type: host, Field: HostName, Value: `vnevado-dc`

End Alert:
Time: 8/14/2024, 10:34:41.578 PM
Name: Ntdsutil collecting Active Directory information
Description: Attackers might be using Ntdsutil to gather information for persistence or to move laterally in a network or organization. Ntdsutil is a command line tool that provides management facilities for Active Directory Domain Services (AD DS) and Active Directory Lightweight Directory Services (AD LDS). It was launched to maintain the database of AD DS.
Entities from this alert:
Type: process, Field: ProcessId__CreatedTimeUtc__CommandLine, Value: `2556__2024-08-01t12:37:29.6522416z__"powershell.exe" -encodedcommand iabuahqazabz...`
##############
Your response:
{
    "context": "As part of a recent multi-stage security incident involving initial access & collection on multiple endpoints, a file `powershell.exe` was launched on host `vnevado-dc`, which might be an indicator of an attacker using Ntdsutil to gather information for persistence or to move laterally in a network or organization. Note: Ntdsutil is a command line tool that provides management facilities for Active Directory Domain Services (AD DS) and Active Directory Lightweight Directory Services (AD LDS). It was launched to maintain the database of AD DS.",
    "question": "When was the last time the file `powershell.exe` was launched on host `vnevado-dc`, and what was the process ID?",
    "answer": "Time: 2024-08-01t12:37:29.6522416, Process Id: 2556"
}
##############
##############
Security Incident: Multi-stage incident involving Execution & Discovery on one endpoint, Description: nan, Severity: Informational, Time of incident: from 2024-06-26 11:57:25.302556+00:00 to 2024-06-26 13:17:18.874531+00:00, Additional Details: {"alertsCount":11,"bookmarksCount":0,"commentsCount":1,"alertProductNames":["Microsoft Defender Advanced Threat Protection"],"tactics":[],"techniques":["T1059","T1112","T1547","T1053","T1018","T1069","T1087","T1135","T1558"]}

Start Alert:
Time: 8/14/2024, 10:34:41.429 PM
Name: Suspicious credential dump from NTDS.dit
Description: Attackers dump NTDS.dit in order to obtain user's credentials which are stored in the domain controller.
Entities from this alert:
Type: process, Field: ProcessId__CreatedTimeUtc__CommandLine, Value: `6748__2024-08-01t12:37:30.2769191z__"ntdsutil.exe" "ac i ntds" ifm "create full c:\\temp" q q`
Type: process, Field: ExtractedFileName, Value: `ntdsutil.exe`

End Alert:
Time: 8/14/2024, 10:37:13.064 PM
Name: Suspicious Azure Resource Management activities by a risky user
Description: Suspicious cloud Azure Resource Management (ARM) activities were performed by a user account that signed in to a risky session. This alert was triggered based on a Microsoft Defender for Cloud alert related to ARM and Microsoft Entra ID Protection risk scores.
Entities from this alert:
Type: account, Field: Email, Value: `Megan Bower@vnevado.alpineskihouse.co`
##############
Your response:
{
    "context": "A Multi-stage security incident involving Execution & Discovery on one endpoint was reported by Microsoft Defender Advanced Threat Protection along with 11 flagged alerts. As part of investigating this incident, we observed a file `ntdsutil.exe` was launched with this command line: `ntdsutil.exe ac i ntds ifm create full c:\temp q q`. The Process ID was 6748. This process might be an indicator of an attacker dumping NTDS.dit in order to obtain user's credentials which are stored in the domain controller.",
    "question: "Related to this alert, there is also a suspicious Azure Resource Management (ARM) activities, which is likely from the same user. Can you get the email of the user who performed the suspicious ARM activities?",
    "answer": "Megan Bower@vnevado.alpineskihouse.co",
}
##############
##############
Security Incident: SAP financial process manipulation (attack disruption), Description: nan, Severity: High, Time of incident: from 2024-07-22 08:18:18.418000+00:00 to 2024-07-22 09:46:21+00:00, Additional Details: {"alertsCount":11,"bookmarksCount":0,"commentsCount":0,"alertProductNames":["Azure Active Directory Identity Protection","Microsoft Cloud App Security","Microsoft 365 Defender"],"tactics":[],"techniques":["T1110","T1564","T1114","T1586","T1078"]}

Start Alert:
Time: 8/14/2024, 10:37:13.079 PM
Name: Malicious URL was clicked on that device
Description: Malicious URL was clicked on that device
Entities from this alert:
Type: url, Field: Url, Value: `https://dj01161621.bravesand-e1ccd718.eastus.azurecontainerapps.io/`
Type: process, Field: ProcessId__CreatedTimeUtc__CommandLine, Value: `4256__2024-08-01t13:42:52.04__"msedge.exe" --type=utility --utility-sub-type=network.mojom.networkservice --lang=en-us --service-sandbox-type=none --field-trial-handle=1912,i,9358546549091360037,1317674413260171076,262144 --variations-seed-version --mojo-platform-channel-handle=3124 /prefetch:11`

End Alert:
Time: 8/14/2024, 10:34:41.429 PM
Name: Suspicious credential dump from NTDS.dit
Description: Attackers dump NTDS.dit in order to obtain user's credentials which are stored in the domain controller.
Entities from this alert:
Type: process, Field: ExtractedFileName, Value: `ntdsutil.exe`
##############
Your response:
{
    "context": "A security incident involving SAP financial process manipulation (attack disruption) occured in our organization as indicated by 11 flagged alerts. One part of this security incident is that a malicious URL `https://dj01161621.bravesand-e1ccd718.eastus.azurecontainerapps.io/` was clicked on Microsoft Edge browser, the ProcessId__CreatedTimeUtc__CommandLine is `4256__2024-08-01t13:42:52.04__"msedge.exe" --type=utility --utility-sub-type=network.mojom.networkservice --lang=en-us --service-sandbox-type=none --field-trial-handle=1912,i,9358546549091360037,1317674413260171076,262144 --variations-seed-version --mojo-platform-channel-handle=3124 /prefetch:11`.",
    "question": "Related to this alert, there is also a suspicious credential dump from NTDS.dit. Can you get the file name of the process that was used to dump the NTDS.dit?",
    "answer": "ntdsutil.exe",
}
##############
"""


#TODO: tweak prompt
QAGEN_PROMPT_ORIGIN = """Your goal is to ask a security question from the given data from a security analyst's perspective.
You are given the start alert and end alert, and corresponding entities. The two alerts are connected by a alert-entity path. The start and end alert might be the same.
You will use the start alert as the context, and ask a question about the entities in the end alert.

The JSON must have the following fields:
- "question": the question about the end alert. The question should be carefully crafted so that:
    1. The question should be natural and relevant to the context, and it should be clear and have a deterministic answer.
    2. But it should not leak the answer. If the start and end alert are the same, you should be more careful since the given entities may have overlapping information.
    3. The question should be specific of the answer you are looking for, and the answer should match the question.
- "answer": the answer to the question. You may be given one or more entities from the end alert, select the most meaningful entity and make sure it is not leaked in the context or question.
- "context": the context from the start alert. you should combine the alert and the entities given in a consistent sentence. You can simplify the context a bit if it is too long. Make sure the answer is not leaked in the context. If the start alert or the related entities contains the answer, you should remove it from the context.

Examples:
##############
Start Alert:
Time: 8/14/2024, 10:34:41.578 PM
Name: Ntdsutil collecting Active Directory information
Description: Attackers might be using Ntdsutil to gather information for persistence or to move laterally in a network or organization. Ntdsutil is a command line tool that provides management facilities for Active Directory Domain Services (AD DS) and Active Directory Lightweight Directory Services (AD LDS). It was launched to maintain the database of AD DS.
Entities from this alert:
Type: process, Field: ExtractedFileName, Value: `powershell.exe`
Type: host, Field: HostName, Value: `vnevado-dc`

End Alert:
Time: 8/14/2024, 10:34:41.578 PM
Name: Ntdsutil collecting Active Directory information
Description: Attackers might be using Ntdsutil to gather information for persistence or to move laterally in a network or organization. Ntdsutil is a command line tool that provides management facilities for Active Directory Domain Services (AD DS) and Active Directory Lightweight Directory Services (AD LDS). It was launched to maintain the database of AD DS.
Entities from this alert:
Type: process, Field: ProcessId__CreatedTimeUtc__CommandLine, Value: `2556__2024-08-01t12:37:29.6522416z__"powershell.exe" -encodedcommand iabuahqazabz...`
##############
Your response:
{
    "context": "A file `powershell.exe` was launched on host `vnevado-dc`, which might be an indicator of an attacker using Ntdsutil to gather information for persistence or to move laterally in a network or organization. Note: Ntdsutil is a command line tool that provides management facilities for Active Directory Domain Services (AD DS) and Active Directory Lightweight Directory Services (AD LDS). It was launched to maintain the database of AD DS.",
    "question": "When was the last time the file `powershell.exe` was launched on host `vnevado-dc`, and what was the process ID?",
    "answer": "Time: 2024-08-01t12:37:29.6522416, Process Id: 2556"
}
##############
##############
Start Alert:
Time: 8/14/2024, 10:34:41.429 PM
Name: Suspicious credential dump from NTDS.dit
Description: Attackers dump NTDS.dit in order to obtain user's credentials which are stored in the domain controller.
Entities from this alert:
Type: process, Field: ProcessId__CreatedTimeUtc__CommandLine, Value: `6748__2024-08-01t12:37:30.2769191z__"ntdsutil.exe" "ac i ntds" ifm "create full c:\\temp" q q`
Type: process, Field: ExtractedFileName, Value: `ntdsutil.exe`

End Alert:
Time: 8/14/2024, 10:37:13.064 PM
Name: Suspicious Azure Resource Management activities by a risky user
Description: Suspicious cloud Azure Resource Management (ARM) activities were performed by a user account that signed in to a risky session. This alert was triggered based on a Microsoft Defender for Cloud alert related to ARM and Microsoft Entra ID Protection risk scores.
Entities from this alert:
Type: account, Field: Email, Value: `Megan Bower@vnevado.alpineskihouse.co`
##############
Your response:
{
    "context": "A file `ntdsutil.exe` was launched with this command line: `ntdsutil.exe ac i ntds ifm create full c:\temp q q`. The Process ID was 6748. This process might be an indicator of an attacker dumping NTDS.dit in order to obtain user's credentials which are stored in the domain controller.",
    "question: "Related to this alert, there is also a suspicious Azure Resource Management (ARM) activities, which is likely from the same user. Can you get the email of the user who performed the suspicious ARM activities?",
    "answer": "Megan Bower@vnevado.alpineskihouse.co",
}
##############
##############
Start Alert:
Time: 8/14/2024, 10:37:13.079 PM
Name: Malicious URL was clicked on that device
Description: Malicious URL was clicked on that device
Entities from this alert:
Type: url, Field: Url, Value: `https://dj01161621.bravesand-e1ccd718.eastus.azurecontainerapps.io/`
Type: process, Field: ProcessId__CreatedTimeUtc__CommandLine, Value: `4256__2024-08-01t13:42:52.04__"msedge.exe" --type=utility --utility-sub-type=network.mojom.networkservice --lang=en-us --service-sandbox-type=none --field-trial-handle=1912,i,9358546549091360037,1317674413260171076,262144 --variations-seed-version --mojo-platform-channel-handle=3124 /prefetch:11`

End Alert:
Time: 8/14/2024, 10:34:41.429 PM
Name: Suspicious credential dump from NTDS.dit
Description: Attackers dump NTDS.dit in order to obtain user's credentials which are stored in the domain controller.
Entities from this alert:
Type: process, Field: ExtractedFileName, Value: `ntdsutil.exe`
##############
Your response:
{
    "context": "A malicious URL `https://dj01161621.bravesand-e1ccd718.eastus.azurecontainerapps.io/` was clicked on Microsoft Edge browser, the ProcessId__CreatedTimeUtc__CommandLine is `4256__2024-08-01t13:42:52.04__"msedge.exe" --type=utility --utility-sub-type=network.mojom.networkservice --lang=en-us --service-sandbox-type=none --field-trial-handle=1912,i,9358546549091360037,1317674413260171076,262144 --variations-seed-version --mojo-platform-channel-handle=3124 /prefetch:11`.",
    "question": "Related to this alert, there is also a suspicious credential dump from NTDS.dit. Can you get the file name of the process that was used to dump the NTDS.dit?",
    "answer": "ntdsutil.exe",
}
##############
"""


REWRITE_PROMPT = """Your goal is to rewrite a given context, question, and answer to make sure the answer is not leaked in the context or question.
The question is contructed from a security analyst's perspective from a security alert graph.
You will also be given the start alert and end alert, and corresponding entities that was used to generate question.
The two alerts are connected by a alert-entity path. The start and end alert might be the same.
Your response should be in JSON format containing 3 fields: "context", "question", and "answer".
"""

SOLUTIN_GEN_PROMPT = """Given an alert-entity path, please generate a solution path, where the question asks about the end entity.
In each step of the solution path, please make sure you include the entity field and value.

Your response should be in JSON format, containing field "solution" which is a list of strings.

Examples:
##############
##############
Solution path:
Time: 8/14/2024, 10:34:41.578 PM
Name: Ntdsutil collecting Active Directory information
Description: Attackers might be using Ntdsutil to gather information for persistence or to move laterally in a network or organization. Ntdsutil is a command line tool that provides management facilities for Active Directory Domain Services (AD DS) and Active Directory Lightweight Directory Services (AD LDS). It was launched to maintain the database of AD DS.
Entities from this alert:
Type: process, Field: ProcessId__CreatedTimeUtc__CommandLine, Value: `6748__2024-08-01t12:37:30.2769191z__"ntdsutil.exe" "ac i ntds" ifm "create full c:\temp" q q`
##############
Your response:
{
    "solution": [
        "The attacker launched ntdsutil with the command line `ntdsutil.exe ac i ntds ifm create full c:\temp q q`." at `2024-08-01t12:37:30.2769191z`, with Process ID `6748`.
    ]
}
##############
##############
Solution path:
Time: 8/14/2024, 10:34:41.578 PM
Name: Ntdsutil collecting Active Directory information
Description: Attackers might be using Ntdsutil to gather information for persistence or to move laterally in a network or organization. Ntdsutil is a command line tool that provides management facilities for Active Directory Domain Services (AD DS) and Active Directory Lightweight Directory Services (AD LDS). It was launched to maintain the database of AD DS.
Entities from this alert:
Type: host, Field: HostName, Value: `vnevado-dc`

Time: 8/14/2024, 10:37:13.045 PM
Name: Azure Resource Manager operation from suspicious proxy IP address
Description: Microsoft Defender for Resource Manager detected a resource management operation from an IP address that is associated with proxy services, such as TOR. While this behavior can be legitimate, it's often seen in malicious activities, when threat actors try to hide their source IP.
Entities from this alert:
Type: ip, Field: Address, Value: `185.220.101.1`

Time: 8/14/2024, 10:37:13.064 PM
Name: Suspicious Azure Resource Management activities by a risky user
Description: Suspicious cloud Azure Resource Management (ARM) activities were performed by a user account that signed in to a risky session. This alert was triggered based on a Microsoft Defender for Cloud alert related to ARM and Microsoft Entra ID Protection risk scores.
Entities from this alert:
Type: account, Field: AadUserId, Value: `6c16dea3-5326-461e-a48e-38b527df3a70`
##############
Your response:
{
    "solution": [
        "There is a collection of active directory information with ntutil.exe on host `vnevado-dc`.",
        "There is a suspicious Azure Resource Manager operation from a proxy IP address `185.220.101.1`.",
        "There is a suspicious Azure Resource Management activities by a risky user with AadUserId `6c16dea3-5326-461e-a48e-38b527df3a70`."

}
#############
#############
Solution path:
Time: 8/14/2024, 10:37:13.011 PM
Name: Email messages containing malicious URL removed after delivery
Description: Emails with malicious URL that were delivered and later removed -V1.0.0.3
Entities from this alert:
Type: account, Field: Name, Value: `Megan Bower`

Time: 8/14/2024, 10:37:12.993 PM
Name: A potentially malicious URL click was detected
Description: We have detected that one of your users has recently clicked on a link that was found to be malicious. -V1.0.0.5
Entities from this alert:
Type: account, Field: Sid, Value: `S-1-5-21-1840151660-3534030288-105586563-1127`
##############
Your response:
{
    "solution": [
        "The email account `Megan Bower` received an email with a malicious URL.",
        "The user with SID `S-1-5-21-1840151660-3534030288-105586563-1127` clicked on the malicious URL."
    ]
}
"""

QAGEN_PROMPT_NO_ENTRY = """Your goal is to ask a security question from the given data from a security analyst's perspective.
You are given an alert-entity graph. The graph starts and ends in entity nodes. Intermediate alert and entities are also given. 

How to use the information provided:
1. The question should be about the end entity (it should be the answer to the question). So NEVER include the end entity in the context or question.
2. Always include start entities (if not all) in the context/question. Use the alert information to connect the context and question.
3. A connecting entity is an entity that is presented in last alert and the next alert. The specific value of the connecting entities will be replace with placeholder `???`. You can reference to them if needed.
4. At repetitive entities: If the entity is also an end entity, you MUST NOT include it in the context/question. If the entity is a start entity, you can include it in the context/question.

Note:
- If there is one alert, that means the start and end alerts are the same.

The JSON must have the following fields:
- "context": the context from the start alert. you should combine the alert and the (start) entities given in a consistent sentence. You can simplify the context a bit if it is too long. Make sure the answer is not leaked in the context. If the start alert or the related entities contains the answer, you should remove it from the context.
    - Try to connect the context and the question in a natural way using the intermediate alerts.
- "question": the question about the end alert. The question should be carefully crafted so that:
    1. The question should be natural and relevant to the context, and it should be clear and have a deterministic answer.
    2. But it should not leak the answer. If the start and end alert are the same, you should be more careful since the given entities may have overlapping information.
    3. The question should be specific of the answer you are looking for, and the answer should match the question.
- "answer": the answer to the question. You may be given one or more entities from the end alert, select the most meaningful entity and make sure it is not leaked in the context or question.

Examples:
##############
Start Entity:
Type: process, Field: ExtractedFileName, Value: `powershell.exe`
Type: host, Field: HostName, Value: `vnevado-dc`

Start Alert:
Time: 2024-08-01 12:54:34.046089+00:00
Name: Ntdsutil collecting Active Directory information
Description: Attackers might be using Ntdsutil to gather information for persistence or to move laterally in a network or organization. Ntdsutil is a command line tool that provides management facilities for Active Directory Domain Services (AD DS) and Active Directory Lightweight Directory Services (AD LDS). It was launched to maintain the database of AD DS.

End Entity:
Type: process, Field: ProcessId__CreatedTimeUtc__CommandLine, Value: `2556__2024-08-01t12:37:29.6522416z__"powershell.exe" -encodedcommand iabuahqazabz...`
##############
Your response:
{
    "context": "A file `powershell.exe` was launched on host `vnevado-dc`, which might be an indicator of an attacker using Ntdsutil to gather information for persistence or to move laterally in a network or organization. Note: Ntdsutil is a command line tool that provides management facilities for Active Directory Domain Services (AD DS) and Active Directory Lightweight Directory Services (AD LDS). It was launched to maintain the database of AD DS.",
    "question": "When was the last time the file `powershell.exe` was launched on host `vnevado-dc`, and what was the process ID?",
    "answer": "Time: 2024-08-01t12:37:29.6522416, Process Id: 2556"
}
##############
##############
Start Entity:
Type: url, Field: Url, Value: `login.micro.demo.antoinetest.ovh`
Type: ip, Field: Address, Value: `231.60.52.209`
Type: ip, Field: Address, Value: `228.3.31.94`

Start Alert:
Time: 2024-08-01 12:47:22.846409+00:00
Name: Malicious Url detected in Proxy logs
Description: Connection from 231.60.52.209 - vnevado-win11h.vnevado.alpineskihouse.co to login.micro.demo.antoinetest.ovh has been seen on the proxy, please check on the computer what happened

Connected Entities:
Type: host, Field: HostName, Value: `???`

Next Alert:
Time: 2024-08-01 13:49:58.880422+00:00
Name: Malicious URL was clicked on that device
Description: Malicious URL was clicked on that device

Connected Entities:
Type: account, Field: Name, Value: `???`

End Alert:
Time: 2024-08-01 13:09:13.222398+00:00
Name: Azure Resource Manager operation from suspicious proxy IP address
Description: Microsoft Defender for Resource Manager detected a resource management operation from an IP address that is associated with proxy services, such as TOR. While this behavior can be legitimate, it's often seen in malicious activities, when threat actors try to hide their source IP.

End Entity:
Type: ip, Field: Address, Value: `253.1.244.215`
##############
Your response:
{
    "context": "Connection from 231.60.52.209 - vnevado-win11h.vnevado.alpineskihouse.co to login.micro.demo.antoinetest.ovh has been seen on the proxy. A malicious URL was clicked on some host by an account."
    "question: "From the same account, the defender detected a resource management operation from an IP address that is associated with proxy services, such as TOR. Can you get the IP address of the proxy?",
    "answer": "253.1.244.215"
}
"""


QAGEN_PROMPT_WITH_ENTRY = """Your goal is to ask a security question from the given data from a security analyst's perspective.
You are given an alert-entity graph. The graph starts and ends in entity nodes. Intermediate alert and entities are also given. 

How to use the information provided:
1. The question should be about the end entity (it should be the answer to the question). So NEVER include the end entity in the context or question.
2. Always include start entities (if not all) in the context/question. Use the alert information to connect the context and question.
3. Try not to include the exact values of connecting entities, or intermediate entites.
4. At repetitive entities: If the entity is also an end entity, you MUST NOT include it in the context/question. If the entity is a start entity, you can include it in the context/question.

Note:
- If there is one alert, that means the start and end alerts are the same.

The JSON must have the following fields:
- "context": the context from the start alert. you should combine the alert and the (start) entities given in a consistent sentence. You can simplify the context a bit if it is too long. Make sure the answer is not leaked in the context. If the start alert or the related entities contains the answer, you should remove it from the context.
    - Try to connect the context and the question in a natural way using the intermediate alerts.
- "question": the question about the end alert. The question should be carefully crafted so that:
    1. The question should be natural and relevant to the context, and it should be clear and have a deterministic answer.
    2. But it should not leak the answer. If the start and end alert are the same, you should be more careful since the given entities may have overlapping information.
    3. The question should be specific of the answer you are looking for, and the answer should match the question.
- "answer": the answer to the question. You may be given one or more entities from the end alert, select the most meaningful entity and make sure it is not leaked in the context or question.

Examples:
##############
Start Entity:
Type: process, Field: ExtractedFileName, Value: `powershell.exe`
Type: host, Field: HostName, Value: `vnevado-dc`

Start Alert:
Time: 2024-08-01 12:54:34.046089+00:00
Name: Ntdsutil collecting Active Directory information
Description: Attackers might be using Ntdsutil to gather information for persistence or to move laterally in a network or organization. Ntdsutil is a command line tool that provides management facilities for Active Directory Domain Services (AD DS) and Active Directory Lightweight Directory Services (AD LDS). It was launched to maintain the database of AD DS.

End Entity:
Type: process, Field: ProcessId__CreatedTimeUtc__CommandLine, Value: `2556__2024-08-01t12:37:29.6522416z__"powershell.exe" -encodedcommand iabuahqazabz...`
##############
Your response:
{
    "context": "A file `powershell.exe` was launched on host `vnevado-dc`, which might be an indicator of an attacker using Ntdsutil to gather information for persistence or to move laterally in a network or organization. Note: Ntdsutil is a command line tool that provides management facilities for Active Directory Domain Services (AD DS) and Active Directory Lightweight Directory Services (AD LDS). It was launched to maintain the database of AD DS.",
    "question": "When was the last time the file `powershell.exe` was launched on host `vnevado-dc`, and what was the process ID?",
    "answer": "Time: 2024-08-01t12:37:29.6522416, Process Id: 2556"
}
##############
##############
Start Entity:
Type: url, Field: Url, Value: `login.micro.demo.antoinetest.ovh`
Type: ip, Field: Address, Value: `231.60.52.209`
Type: ip, Field: Address, Value: `228.3.31.94`

Start Alert:
Time: 2024-08-01 12:47:22.846409+00:00
Name: Malicious Url detected in Proxy logs
Description: Connection from 231.60.52.209 - vnevado-win11h.vnevado.alpineskihouse.co to login.micro.demo.antoinetest.ovh has been seen on the proxy, please check on the computer what happened

Connected Entities:
Type: host, Field: HostName, Value: `vnevado-win11h`

Next Alert:
Time: 2024-08-01 13:49:58.880422+00:00
Name: Malicious URL was clicked on that device
Description: Malicious URL was clicked on that device

Connected Entities:
Type: account, Field: Name, Value: `Hailey Johnson`

End Alert:
Time: 2024-08-01 13:09:13.222398+00:00
Name: Azure Resource Manager operation from suspicious proxy IP address
Description: Microsoft Defender for Resource Manager detected a resource management operation from an IP address that is associated with proxy services, such as TOR. While this behavior can be legitimate, it's often seen in malicious activities, when threat actors try to hide their source IP.

End Entity:
Type: ip, Field: Address, Value: `253.1.244.215`
##############
Your response:
{
    "context": "Connection from 231.60.52.209 - vnevado-win11h.vnevado.alpineskihouse.co to login.micro.demo.antoinetest.ovh has been seen on the proxy. A malicious URL was clicked on this host `vnevado-win11h` by some account."
    "question: "From the same account, the defender detected a resource management operation from an IP address that is associated with proxy services, such as TOR. Can you get the IP address of the proxy?",
    "answer": "253.1.244.215"
}
"""