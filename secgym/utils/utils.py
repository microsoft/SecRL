# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.


import requests
from bs4 import BeautifulSoup
import re
import json
import yaml
import os
import Levenshtein
import autogen

from openai import APITimeoutError

def msging(msg, role="user"): 
    return {"role": role, "content": msg}

def get_full_question(question_dict, add_hint=False):
    if add_hint:
        return f"{question_dict.get('context', '')} {question_dict['question']} \n Here is the hint to this questions: {question_dict['hint']}".strip()
    return f"{question_dict.get('context', '')} {question_dict['question']}".strip()


def LLM_call(instruction: str, task: str, config_list: list, return_cost:bool = False, retry = 10, is_o1=False, **args) -> str:
    # Anthropic (Claude / Opus) models: call the SDK directly. autogen's OpenAI
    # wrapper does not reliably support newer reasoning models (pricing/params),
    # so we bypass it when the target config is an Anthropic endpoint.
    anthropic_cfg = next((c for c in config_list if c.get("api_type") == "anthropic"), None)
    if anthropic_cfg is not None:
        import anthropic as _anthropic
        _client = _anthropic.Anthropic(api_key=anthropic_cfg["api_key"])
        max_tokens = anthropic_cfg.get("max_tokens", 8192)
        content = ""
        for r in range(retry):
            try:
                resp = _client.messages.create(
                    model=anthropic_cfg["model"],
                    max_tokens=max_tokens,
                    system=instruction,
                    messages=[{"role": "user", "content": task}],
                )
                content = "".join(
                    b.text for b in resp.content if getattr(b, "type", None) == "text"
                )
                break
            except Exception:
                if r == retry - 1:
                    raise
                continue
        print(content)
        return (content, 0.0) if return_cost else content

    client = autogen.OpenAIWrapper(
        config_list=config_list,
        **args
    )
    #print(args)
    #print(config_list)
    for r in range(retry):
        try:
            messages = [{'role': 'system', 'content': instruction}, {'role': 'user', 'content': task}]
            if is_o1:
                messages[0]['role'] = 'user'
            #print(is_o1)
            #print(messages)
            response = client.create(messages=messages)
        except APITimeoutError as e:
            continue
        break
    print(response.choices[0].message.content)
    if return_cost:
        return response.choices[0].message.content, response.cost
    return response.choices[0].message.content

def process_entity_identifiers(entities_json_string):
    try:
        entity_dict_list = json.loads(entities_json_string)
    except:
        return []

    def is_local_ipv4(ip_address):
        try:
            if ip_address == "0.0.0.0" or ip_address == "127.0.0.1" or ip_address[:7] == "192.168" or ip_address[:3] == "10.":
                return True
            elif (ip_address[0:4] == "172."):
                ip_address_fields = ip_address.split(".")
                if len(ip_address_fields) >= 2:
                    ip_range = int(ip_address_fields[1])
                    if ip_range >= 16 and ip_range <= 32:
                        return True
            
            return False
        except:
            return False

    def get_identifier_value(entity_dict, identifier_field):
        return str(entity_dict[identifier_field]).lower() if identifier_field in entity_dict else ""
    
    entity_field_delimiter = "__"
    def union_fields(identifier_list):
        str_identifier_list = [str(identifier).lower() for identifier in identifier_list]
        return entity_field_delimiter.join(str_identifier_list)

    final_entities_list = []

    for entity_dict in entity_dict_list:
        if "Type" in entity_dict:
            type_value = entity_dict["Type"].lower()
            node_attributes = {"node_type": type_value}
            

            if type_value == "account":

                identifier_field = "AadUserId"
                identifier_value = get_identifier_value(entity_dict, identifier_field)

                if "Name" in entity_dict and entity_dict["Name"] not in ["root", "system", "guest", "admin", "administrator", "user"]:
                    node_attributes['identifier_fields'] = "Name"
                    final_entities_list.append([type_value, "Name", entity_dict["Name"], json.dumps(node_attributes.copy())])

                if "Name" in entity_dict and entity_dict["Name"] not in ["root", "system", "guest", "admin", "administrator", "user"] and "UPNSuffix" in entity_dict:
                    node_attributes['identifier_fields'] = "Email"
                    # Use the authoritative email/UPN rather than synthesizing it from the
                    # display name. The Sentinel Account entity `Name` field is provider
                    # dependent and frequently holds the display name (e.g. "Jordan P"),
                    # which would yield an address that does not exist in the logs. Prefer
                    # the real UserPrincipalName, then AccountName@Domain, and only fall
                    # back to Name@UPNSuffix when neither is available.
                    upn = entity_dict.get("UserPrincipalName")
                    account_name = entity_dict.get("AccountName")
                    domain = entity_dict.get("DomainName") or entity_dict.get("UPNSuffix")
                    if upn:
                        email_value = upn
                    elif account_name and domain:
                        email_value = f"{account_name}@{domain}"
                    else:
                        email_value = entity_dict["Name"] + "@" + entity_dict['UPNSuffix']
                    final_entities_list.append([type_value, "Email", email_value, json.dumps(node_attributes.copy())])
                
                if "Sid" in entity_dict:
                    if entity_dict["Sid"] in ['S-1-5-18']: continue
                    node_attributes['identifier_fields'] = "Sid"
                    final_entities_list.append([type_value, "Sid", entity_dict["Sid"], json.dumps(node_attributes.copy())])
                
                node_attributes['identifier_fields'] = "AadUserId"

            elif type_value == "cloud-application":

                identifier_field = "AppId"
                identifier_value = get_identifier_value(entity_dict, identifier_field)

                if "Name" in entity_dict and "InstanceName" in entity_dict:
                    node_attributes['identifier_fields'] = "Name__InstanceName"
                    final_entities_list.append([type_value, "Name__InstanceName", union_fields([entity_dict["Name"], entity_dict['InstanceName']]), json.dumps(node_attributes.copy())])
                
                node_attributes['identifier_fields'] = "AppId"

            elif type_value == "file":

                identifier_field = "Name"
                identifier_value = get_identifier_value(entity_dict, identifier_field)

                # if "Name" in entity_dict and "Directory" in entity_dict:
                #     final_entities_list.append([type_value, "Directory__Name", entity_dict['Directory'] + entity_field_delimiter + entity_dict["Name"], json.dumps(node_attributes.copy())])
                node_attributes['identifier_fields'] = "Name"

            elif type_value == "filehash":

                if "Algorithm" in entity_dict and "Value" in entity_dict:
                    node_attributes['identifier_fields'] = "Algorithm__Value"
                    final_entities_list.append([type_value, "Algorithm__Value", union_fields([entity_dict["Algorithm"], entity_dict["Value"]]), json.dumps(node_attributes.copy())])
                
                continue

            elif type_value == "host":

                identifier_field = "AadDeviceId"
                identifier_value = get_identifier_value(entity_dict, identifier_field)

                if "AzureID" in entity_dict:
                    node_attributes['identifier_fields'] = "AzureID"
                    final_entities_list.append([type_value, "AzureID", entity_dict["AzureID"], json.dumps(node_attributes.copy())])

                if "HostName" in entity_dict:
                    node_attributes['identifier_fields'] = "HostName"
                    final_entities_list.append([type_value, "HostName", entity_dict["HostName"], json.dumps(node_attributes.copy())])

                if "OMSAgentID" in entity_dict:
                    node_attributes['identifier_fields'] = "OMSAgentID"
                    final_entities_list.append([type_value, "OMSAgentID", entity_dict["OMSAgentID"], json.dumps(node_attributes.copy())])

                node_attributes['identifier_fields'] = "AadDeviceId"

            elif type_value == "iotdevice":

                identifier_field = "DeviceId"
                node_attributes['identifier_fields'] = "DeviceId"
                identifier_value = get_identifier_value(entity_dict, identifier_field)

            elif type_value == "ip":

                identifier_field = "Address"
                node_attributes['identifier_fields'] = "Address"
                identifier_value = get_identifier_value(entity_dict, identifier_field)
                if identifier_value in ('0.0.0.0', '127.0.0.1', '8.8.8.8'): continue
                node_attributes['IsLocalIPv4'] = str(is_local_ipv4(identifier_value))
                #if is_local_ipv4(identifier_value): continue
            
            elif type_value == "mailbox" or type_value == "mailboxconfiguration":

                identifier_field = "MailboxPrimaryAddress"
                node_attributes['identifier_fields'] = "MailboxPrimaryAddress"
                identifier_value = get_identifier_value(entity_dict, identifier_field)

            elif type_value == "mailcluster":

                if "Source" in entity_dict and "Query" in entity_dict:
                    node_attributes['identifier_fields'] = "Source__Query"
                    final_entities_list.append([type_value, "Source__Query", union_fields([entity_dict["Source"], entity_dict["Query"]]), json.dumps(node_attributes.copy())])
                
                continue
            
            elif type_value == "mailmessage":

                identifier_field = "Sender"
                identifier_value = get_identifier_value(entity_dict, identifier_field)

                if "Subject" in entity_dict: node_attributes['subject'] = entity_dict['Subject']

                if "Recipient" in entity_dict:
                    node_attributes['identifier_fields'] = "Recipient"
                    final_entities_list.append([type_value, "Recipient", entity_dict["Recipient"], json.dumps(node_attributes.copy())])

                if "SenderIP" in entity_dict and entity_dict["SenderIP"] not in ('0.0.0.0', '127.0.0.1', '8.8.8.8'):
                    node_attributes['identifier_fields'] = "SenderIP"
                    ip_address = entity_dict["SenderIP"]
                    copy_node_attributes = node_attributes.copy()
                    copy_node_attributes['IsLocalIPv4'] = str(is_local_ipv4(ip_address))
                    final_entities_list.append([type_value, "SenderIP", ip_address, json.dumps(copy_node_attributes)])
                
                node_attributes['identifier_fields'] = "Sender"

            elif type_value == "oauth-application":

                identifier_field = "OAuthObjectId"
                identifier_value = get_identifier_value(entity_dict, identifier_field)

                if "OAuthAppId" in entity_dict:
                    node_attributes['identifier_fields'] = "OAuthAppId"
                    final_entities_list.append([type_value, "OAuthAppId", entity_dict["OAuthAppId"], json.dumps(node_attributes.copy())])
                
                node_attributes['identifier_fields'] = "OAuthObjectId"
            
            elif type_value == "process":

                if "ProcessId" in entity_dict and "CreatedTimeUtc" in entity_dict and "CommandLine" in entity_dict:
                    node_attributes['identifier_fields'] = "ProcessId__CreatedTimeUtc__CommandLine"
                    final_entities_list.append([type_value, "ProcessId__CreatedTimeUtc__CommandLine", union_fields([entity_dict["ProcessId"], entity_dict["CreatedTimeUtc"], entity_dict["CommandLine"]]), json.dumps(node_attributes.copy())])

                if "CommandLine" in entity_dict:
                    node_attributes['identifier_fields'] = "ExtractedFileName"
                    command_line = str(get_identifier_value(entity_dict, "CommandLine")).lower()
                    extracted_files = re.findall(r'([^\\\/\s"\']*\.(?:exe|pdf|dll|xlsx|docx|zip|png|txt|ps1|html|png|tmp))', command_line)
                    for extracted_file in extracted_files:
                        final_entities_list.append([type_value, "ExtractedFileName", extracted_file, json.dumps(node_attributes.copy())])

                continue
            
            elif type_value == "security-group":

                identifier_field = "ObjectGuid"
                identifier_value = get_identifier_value(entity_dict, identifier_field)

                if "SID" in entity_dict:
                    node_attributes['identifier_fields'] = "SID"
                    final_entities_list.append([type_value, "SID", entity_dict["SID"], json.dumps(node_attributes.copy())])
                
                node_attributes['identifier_fields'] = "ObjectGuid"

            elif type_value == "service-principal":

                identifier_field = "ServicePrincipalObjectId"
                node_attributes['identifier_fields'] = "ServicePrincipalObjectId"
                identifier_value = get_identifier_value(entity_dict, identifier_field)
            
            elif type_value == "url":

                identifier_field = "Url"
                node_attributes['identifier_fields'] = "Url"
                identifier_value = get_identifier_value(entity_dict, identifier_field)
            #     # TODO: add method to check if url is absolute or not
                #node_attributes['IsAbsoluteUrl'] = str(is_absolute_url(identifier_value))
            
            elif type_value == "azure-resource":

                identifier_field = "ResourceId"
                resource_url = str(get_identifier_value(entity_dict, identifier_field)).lower()
                identifier_value = resource_url

                subscription_match = re.search(r'(?<=subscriptions/)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', resource_url)                
                if subscription_match:
                    node_attributes['identifier_fields'] = "SubscriptionId"
                    final_entities_list.append([type_value, "SubscriptionId", subscription_match.group(), json.dumps(node_attributes.copy())])

                resource_group_list = re.findall(r'resourcegroups/([^/]*)/', resource_url)
                if len(resource_group_list):
                    node_attributes['identifier_fields'] = "ResourceGroup"
                    final_entities_list.append([type_value, "ResourceGroup", resource_group_list[0], json.dumps(node_attributes.copy())])

                node_attributes['identifier_fields'] = "ResourceId"

            else:
                continue
            
            if identifier_value != "":
                final_entities_list.append([type_value, identifier_field, identifier_value, json.dumps(node_attributes)])
    
    return final_entities_list


def scrap_table_schema(table_name, yaml_filename, save_yaml=True):
    yaml_filename = f"data/schema/{table_name}.yaml"
    url = f"""https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/{table_name.lower()}"""

    response = requests.get(url)
    if response.status_code != 200:
        print(f"Failed to fetch the URL: {url}")
        return None
    html_content = response.text
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Extract the description using regex
    pattern = re.compile(r'</nav><!-- <content> --><p>(.*?)</p>', re.DOTALL)
    try:
        description = pattern.findall(str(soup))[0] 
    except IndexError:
        print(f"Description not found for table: {table_name}")
        description = 'N/A'
    else:
        print(f"Description found for table: {table_name}")
        
    # Extract column details
    columns_table = soup.find('h2', id='columns').find_next('table')
    columns = []
    for row in columns_table.find('tbody').find_all('tr'):
        cells = row.find_all('td')
        column_data = {
            'Name': cells[0].text.strip(),
            'Type': cells[1].text.strip(),
            'Description': cells[2].text.strip()
        }
        columns.append(column_data)
    
    # Create the result dictionary
    result = {
        'Name': table_name,
        'InternalName': table_name,
        'Description': description,
        'Conditions': 'N/A',  # Assuming this is a static value
        'Columns': columns
    }
    
    # Convert the result to JSON
    result_json = json.dumps(result, indent=4)
    
    # save_yaml save the original HTML content to a file
    if save_yaml:
        with open(yaml_filename, 'w', encoding='utf-8') as file:
            yaml.dump(result, file, sort_keys=False, default_flow_style=False)

    return result_json


def load_yaml(yaml_filename):
    with open(yaml_filename, 'r', encoding='utf-8') as file:
        data = yaml.load(file, Loader=yaml.FullLoader)
    return data


def find_most_similar(target, strings):
    """
    Finds the most similar string to the target in the given list of strings.

    Parameters:
    - target (str): The string to compare against the list.
    - strings (list of str): The list of strings to search through.

    Returns:
    - str: The most similar string from the list.
    """
    most_similar = None
    highest_similarity = float('inf')
    
    for string in strings:
        similarity = Levenshtein.distance(target, string)
        if similarity < highest_similarity:
            highest_similarity = similarity
            most_similar = string
    
    return most_similar



if __name__ == '__main__':

    files = os.listdir('data/tables')

    for file in files:
        table_name = file.split('.')[0]
        yaml_filename = f"data/schema/{table_name}.yaml"
        result_json = scrap_table_schema(table_name, yaml_filename)
        # print(result_json)
        # data = load_yaml(yaml_filename)
        # print(data)
        # print()
    