# Security AI Agent BRAMA

AI Agent Brama can help you check the security metrics and safety of the following resources: 
* Text messages, 
* Site URL, 
* Email, 
* Phone number, 
* SMS. 

You can also use the educational mode to learn more about social engineering and cybersecurity threats, such as scams and phishing.

Some platforms, like email services, constantly improve their spam filters, and cyber criminals are learning to bypass them. Many channels are hard to protect, like direct calls, SMS, and messengers. These channels are used for phishing, scams, and vishing.

![Security AI Agent BRAMA](AI-Agent-BRAMA-for-security.png)

*BRAMA agent* is going to help users receive additional context regarding suspicious emails, messages, and SMS.

Agent utilize Anthropic Claude Models to analize the conext. 
Together with information from 3d party APIs and resources, the agent can provide additional context:
* Whether the URL was marked as malicious or used for phishing
* Whether the phone number that is calling/sending SMS to you is being used for scams, phishing, or other suspicious activities
* Check the sender's email and content  
* Checks the Domain-based Message Authentication, Reporting, and Conformance (DMARC) record of a domain

After processing by the BRAMA agent, you will receive a comprehensive analysis of the messages or content, providing you with the necessary information to make informed decisions.

If the input contains multiple data types to check (domain, phone, email), we call agent tools one by one.
Note: Some cases can work with errors. Error management needs to be improved.

**Disclaimer:** The agent will process the information using the Anthropic API check https://www.anthropic.com/legal/consumer-terms.
If you do not agree with the agent's conclusions or find an error, create an issue https://github.com/oborys/security-ai-agent-brama/issues


# Installation

Clone the repository
```bash
git clone https://github.com/oborys/security-ai-agent-brama.git
```
Go to your project folder
```bash
cd security-ai-agent-brama
```

Set up a Python venv

To get started, ensure that Python 3 is installed on your machine. Then, we'll create a virtual environment using venv to keep our project dependencies separate from the rest of the system.

Install virtualenv via pip
```bash
pip install virtualenv
```

Create the venv
```bash
python3 -m venv venv
```

Activate your venv
```bash
source venv/bin/activate
```

Install dependencies
```bash
pip install -r requirements.txt
```

## Configuration. Set related API Key

The project utilized 3d party APIs.

A Majority of APIs are free with usage limitations; you need to register and retrieve your API Key.

1. Get the Anthropic API Key here [https://console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys)

Set Anthropic API Key as an environment variable in your virtual environment:

```bash
export ANTHROPIC_API_KEY="YOUR_API_KEY"
```

2. Get VirusTotal API Key here [https://www.virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)

VirusTotal inspects items with over 70 antivirus scanners and URL/domain blocklisting services, in addition to a myriad of tools to extract signals from the studied content. 

Set VirusTotal API Key as an environment variable in your virtual environment:

```bash
export VT_API_KEY="YOUR_API_KEY"
```

3. Get Brave API Key here [https://api.search.brave.com/register](https://api.search.brave.com/register)

The agent uses Brave Search API to search for information about phone numbers. Then, we use this information for further analysis.

Set Brave API Key as an environment variable in your virtual environment:
```bash
export BRAVE_API_KEY="YOUR_API_KEY"
```

4. Get Voyage AI API Key here [https://dash.voyageai.com/api-keys](https://dash.voyageai.com/api-keys)

Voyage AI provides cutting-edge embedding and rerankers.
Embedding models are neural net models (e.g., transformers) that convert unstructured and complex data, such as documents, images, audio, videos, or tabular data, into dense numerical vectors (i.e., embeddings) that capture their semantic meanings.

Embedding is used in the agent's Educational mode. In this mode, users can interact with an assistant and learn information by utilizing information from one of the PDFs connected with social engineering.

Set Voyage API Key as an environment variable in your virtual environment:

```bash
export VOYAGE_API_KEY="YOUR_API_KEY"
```

5. Get URLhaus Auth-Key here [https://auth.abuse.ch/](https://auth.abuse.ch/)

Set URLhaus Auth-Key as an environment variable in your virtual environment:

```bash
export URL_HAUSE_KEY="YOUR_Auth_KEY"
```

7. Get Cisco Umbrella API Key here [https://signup.umbrella.com/](https://signup.umbrella.com/) 

[Add Umbrella API Key documentation](https://docs.umbrella.com/umbrella-user-guide/docs/add-umbrella-api-keys)

Set Umbrella as an environment variable in your virtual environment:

```bash
export UMBRELLA_API_CLIENT="YOUR_Umbrella_API_Client"
```

```bash
export UMBRELLA_API_SECRET="YOUR_Umbrella_API_Secret"
```


## Usage

Run the agent
```bash
python agentBrama.py  
```

Expected output:
```bash
Hi, this is an AI Agent Brama, who can help you check the security metrics and safety of the following resources: 
Text messages, Site URL, Email, Phone number, and SMS. You can also use the educational mode to learn more about social engineering and cybersecurity threats, such as scams and phishing.

Enter a URL, message, or write 'img', 'screenshot', or 'image' to attach an image, or 'education_mode' or 'quit' to exit: 
```

**Work with URL**

Type in malicious URL
```bash
http://117.222.254.157:39234/Mozi.m
```

Or type in malicious URL
```bash
jwgruop.com
```

Expected output:
![img](img/agent-output-sample-domain.png)


**Work with Screenshots**

In the `img` folder of the reposytory there are a few screenshot of the messages that you can use.

Type in img
```bash
Enter a URL, message, or write 'img', 'screenshot', or 'image' to attach an image, or 'education_mode' or 'quit' to exit: img
```

Then provide a path to the image
[path]/Users/oleksa/ml/agent/security-ai-agent-brama/img/phishing-sms.png

Expected output:
![img](img/agent-output-sample-image.png)

**Work with Phone Numbers**

Type in number `202-221-7923`

Expected output:

![img](img/agent-output-sample-phone-number.png)

## Educational mode

![img](img/educational_mode.png)

## YouTube video

[![Creating an AI agent for Cybersecurity](https://img.youtube.com/vi/G1MVWl91k3E/0.jpg)](https://www.youtube.com/watch?v=G1MVWl91k3E)

## Roadmap

* Improve Educational components
* Developed feature that can check public information authorized and verified person in socials and highlight which data is available for cybercrime and can be used against person
* Sent reports about malicious/phishing URL or domains to the security organizations that collect this information
* Multimodal audio recognition for phone calls using https://github.com/fixie-ai/ultravox
* Add Agent Protocol for interaction with another agents https://agentprotocol.ai/
