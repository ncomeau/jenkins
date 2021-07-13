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


#with open('image_scan.json') as f:
with open(sys.argv[1]) as f:
    data = json.load(f)
    vuln = data['vulnerabilities']
    full_repo_name = data['full_tag']
    repo_name = data['repo']
    registry = data['registry']
    tag = data['tag']
    manifest_digest = data['manifest_digest']
    vuln_num = len(data['vulnerabilities'])
    layers = data['image_metadata']['layer_count']

    scan_url = "https://defense-prod05.conferdeploy.net/kubernetes/image/{}/overview".format(manifest_digest)

    if len(vuln) != 0:

        fieldnames = ['CVE', 'Package Name', 'Package Version', 'Package Type', 'Severity', 'Fix Available',
                      'CVSS']

        csvname = '{}_{}_CBC_image_validate.csv'.format(repo_pretty(repo_name), tag)

        with open(csvname, 'w+', newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()

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

                writer.writerow(
                    {'CVE': cve, 'Package Name': pkg_name, 'Package Version': pkg_ver, 'Package Type': pkg_type,
                     'Severity': severity, 'Fix Available': fix, 'CVSS': cvss})
            csvfile.close()

            body = [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*You have a new CBC Image Scan Result for _'{}'_:*\n*<{}|CBC Image Scan Results>*".format(repo_name+":"+tag, scan_url)
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Number of Vulns Found:* _{}_\n*Repo:* {}\n*Registy:* {}\n*Image Layers:* {}\n*Full Image Repo*: <https://hub.docker.com/r/{}|{}>\n*Hash:* {}".format(vuln_num, repo_name, registry, layers, repo_name, full_repo_name, manifest_digest)
                    },
                    "accessory": {
                        "type": "image",
                        "image_url": "https://www.axonius.com/hs-fs/hubfs/Adapter%20Logos/VMW%20Carbon%20Black%20Cloud%20Product%20Icon.png?length=600&name=VMW%20Carbon%20Black%20Cloud%20Product%20Icon.png",
                        "alt_text": "CBC Container Security"
                    }
                }
            ]

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
