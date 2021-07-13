import logging
import sys
# Load the local source directly
sys.path.insert(1, "./python-slack-sdk")

from slack_sdk import WebClient
import json
import csv

# WebClient insantiates a client that can call API methods
# When using Bolt, you can use either `app.client` or the `client` passed to listeners.
client = WebClient(token=os.environ.get('SLACK_TOKEN'))
logger = logging.getLogger(__name__)
# ID of channel you want to post message to
channel_id = "C026HLPCACF"


def repo_pretty(list1):
    return str(list1).replace("/", "+")

def format_url(list1):
    return list1.replace(" ", "+")

with open(sys.argv[1]) as f:

    data = json.load(f)

    if len(data['policy_violations']) != 0:
        full_repo_name = data['full_tag']
        repo_name = data['repo']
        registry = data['registry']
        tag = data['tag']
        manifest_digest = data['manifest_digest']
        violation_num = len(data['policy_violations'])


        head = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Looks like you have a _{}_ CBC K8s Policy conflicts with the image _'{}'_*\n *<https://defense-prod05.conferdeploy.net/kubernetes/repos|CBC K8s Images>*".format(violation_num,repo_name)
                }
            }
        ]

        result = client.chat_postMessage(
            channel=channel_id,
            blocks=head
        )


        for x in range(len(data['policy_violations'])):
            policy = data['policy_violations'][x]['policy']
            rule = data['policy_violations'][x]['rule']
            risk = data['policy_violations'][x]['risk']

            csvname = '{}_{}_CBC_validate.csv'.format(repo_pretty(repo_name), rule)
            fieldnames = ['CVE', 'Package Name', 'Package Version', 'Package Type', 'Severity', 'Fix Available',
                          'CVSS']

            with open(csvname, 'w+', newline="") as csvfile:

                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                writer.writeheader()



                vuln = data['policy_violations'][x]['violation']['scanned'][0]['vulnerabilities']



                for v in range(len(vuln)):

                    cve = vuln[v]['id']
                    pkg_name = vuln[v]['package_name']
                    pkg_ver = vuln[v]['package_version']
                    pkg_type = vuln[v]['package_type']
                    severity = vuln[v]['severity']
                    try:
                        fix = vuln[v]['fix_available']
                    except:
                        fix = "No Fix Found"
                    cvss = vuln[v]['cvss']

                    writer.writerow({'CVE': cve, 'Package Name': pkg_name, 'Package Version': pkg_ver, 'Package Type': pkg_type, 'Severity': severity, 'Fix Available': fix, 'CVSS': cvss})
                csvfile.close()

            if rule == "Critical vulnerabilities":
                body = [
                {
                    "type": "divider"
                },
        {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*<https://defense-prod05.conferdeploy.net/vulns/container_images/containers_vulnerabilities_table/critical?running_in_k8s=false|{0}>*\n*CBC K8s Policy*: {1}\n*Risk*: {2}\n*Full Image Repo*: <https://hub.docker.com/r/{3}|{4}>".format(rule, policy,risk, repo_name,full_repo_name)
                    },
                    "accessory": {
                        "type": "image",
                        "image_url": "https://www.axonius.com/hs-fs/hubfs/Adapter%20Logos/VMW%20Carbon%20Black%20Cloud%20Product%20Icon.png?length=600&name=VMW%20Carbon%20Black%20Cloud%20Product%20Icon.png",
                        "alt_text": "calendar thumbnail"
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "image",
                            "image_url": "https://api.slack.com/img/blocks/bkb_template_images/notificationsWarningIcon.png",
                            "alt_text": "notifications warning icon"
                        },
                        {
                            "type": "mrkdwn",
                            "text": "*CBC K8s Policy _'{}'_ has a Conflict with Container Image _'{}'_*".format(policy,repo_name)
                        }
                    ]
                }
                ]
                # Call the conversations.list method using the WebClient
                result = client.chat_postMessage(
                    channel=channel_id,
                    blocks=body

                )
                upload = client.files_upload(
                    channels=channel_id,
                    file=csvname,
                    filename=csvname,
                    filetype='csv',
                    title=csvname)

                print(result)
                print(upload)
            else:
                body = [
                    {
                        "type": "divider"
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*<https://defense-prod05.conferdeploy.net/kubernetes/policy/rules?searchDefinition={{%22sort%22:[{{%22field%22:%22RULE_NAME%22,%22order%22:%22DESC%22}}]}}&search={0}|{1}>*\n*CBC K8s Policy*: {2}\n*Risk*: {3}\n*Full Image Repo*: <https://hub.docker.com/r/{4}|{5}>".format(
                                format_url(rule), rule, policy, risk, repo_name, full_repo_name)
                        },
                        "accessory": {
                            "type": "image",
                            "image_url": "https://www.axonius.com/hs-fs/hubfs/Adapter%20Logos/VMW%20Carbon%20Black%20Cloud%20Product%20Icon.png?length=600&name=VMW%20Carbon%20Black%20Cloud%20Product%20Icon.png",
                            "alt_text": "CBC Container Security"
                        }
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "image",
                                "image_url": "https://api.slack.com/img/blocks/bkb_template_images/notificationsWarningIcon.png",
                                "alt_text": "notifications warning icon"
                            },
                            {
                                "type": "mrkdwn",
                                "text": "*CBC K8s Policy _'{}'_ has a Conflict with Container Image _'{}'_*".format(
                                    policy, repo_name)
                            }
                        ]
                    }
                ]
                # Call the conversations.list method using the WebClient
                result = client.chat_postMessage(
                    channel=channel_id,
                    blocks=body

                )
                upload = client.files_upload(
                    channels=channel_id,
                    file=csvname,
                    filename=csvname,
                    filetype='csv',
                    title=csvname)

                print(result)
                print(upload)
        # Print result, which includes information about the message (like TS)
