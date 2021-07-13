import logging
import sys
# Load the local source directly
sys.path.insert(1, "./python-slack-sdk")
from slack_sdk import WebClient
import json



# WebClient insantiates a client that can call API methods
# When using Bolt, you can use either `app.client` or the `client` passed to listeners.
client = WebClient(token=os.environ.get('SLACK_TOKEN'))
logger = logging.getLogger(__name__)
# ID of channel you want to post message to
channel_id = "C026HLPCACF"

rules = []
risk = []
both = []


def pretty(list1):
	return str(list1).replace("[", "").replace("]", "").replace("(","").replace(")","").replace('"','').replace("\\\\","\\")

def format_url(list1):
	return list1.replace(" ","+")


with open(sys.argv[1]) as f:

	data = json.load(f)
	print(data)
	print(data['objects'][0]['policy_violations'])



	if len(data['objects'][0]['policy_violations']) != 0:
		yaml_name = data['objects'][0]['file_path']
		policy = data['objects'][0]['policy']
		app_name = data['objects'][0]['name']

		title = [
			{
				"type": "section",
				"text": {
					"type": "mrkdwn",
					"text": "*The Yaml file _'{}'_ has {} violations - based on CBC K8s Policy _'{}'_:*\n_<https://defense-prod05.conferdeploy.net/kubernetes/policy/hardening-policies|Click Here to View Your CBC K8s Policies>_".format(yaml_name,len(data['objects'][0]['policy_violations']),policy)
				}
			},
			{
				"type": "divider"
			}
		]

		result = client.chat_postMessage(
			channel=channel_id,
			blocks=title
		)

		for x in range(len(data['objects'][0]['policy_violations'])):
			rule = data['objects'][0]['policy_violations'][x]['rule']
			risk = data['objects'][0]['policy_violations'][x]['risk']
			both.append(rule+" - "+risk)
			if risk == 'LOW':
				star = "★"
			if risk == 'MEDIUM':
				star= "★★★"
			if risk == 'HIGH':
				star="★★★★"
			if risk == 'CRITICAL':
				star="★★★★★"
			body = [
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*<https://defense-prod05.conferdeploy.net/kubernetes/policy/rules?searchDefinition={{%22sort%22:[{{%22field%22:%22RULE_NAME%22,%22order%22:%22DESC%22}}]}}&search={0}|{1}>*\n*Risk* = {2}\n*App Name* = {3}\n*Policy* = {4}".format(format_url(rule),rule, star,app_name,policy )
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
					"image_url": "https://api.slack.com/img/blocks/bkb_template_images/tripAgentLocationMarker.png",
					"alt_text": "Location Pin Icon"
				},
				{
					"type": "plain_text",
					"text": "File: {}".format(yaml_name)
				}
			]
		},
		{
			"type": "divider"
		}
	]
			# Call the conversations.list method using the WebClient
			result = client.chat_postMessage(
				channel=channel_id,
				blocks=body
		)
		# Print result, which includes information about the message (like TS)
		print(result)
